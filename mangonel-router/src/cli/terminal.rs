//! The wizard's questions as `inquire` prompts.

use std::fmt;

use inquire::{
    CustomUserError,
    InquireError,
    Select,
    Text,
    error::InquireResult,
    ui::{
        Color,
        RenderConfig,
        Styled,
    },
    validator::Validation,
};

use crate::{
    cli::{
        device::Device,
        wizard::{
            Error,
            Field,
            Prompt,
            Reply,
        },
    },
    config::{
        Family,
        Invalid,
        Method,
        Role,
    },
};

/// What a list says about its keys when there is no question to go back to.
const LIST_HELP: &str = "↑↓ to move, enter to select, type to filter";

/// What a list says about its keys.
const LIST_HELP_BACK: &str = "↑↓ to move, enter to select, type to filter, ctrl+d to go back";

/// What a typed question says about its keys.
const TEXT_HELP: &str = "ctrl+d to go back";

/// Asks on the terminal.
pub(crate) struct Terminal {
    render: RenderConfig<'static>,
}

impl Terminal {
    pub(crate) fn new() -> Self {
        // inquire marks a question that was left as canceled; here leaving one is going back.
        let back = Styled::new("<back>").with_fg(Color::DarkRed);

        Self {
            render: RenderConfig::default().with_canceled_prompt_indicator(back),
        }
    }

    /// Asks for one of `choices`, each a label and what it stands for, starting on `initial`.
    fn select<T: Copy + PartialEq>(
        &self,
        title: &str,
        choices: &[(String, T)],
        initial: Option<T>,
        help: &str,
    ) -> Result<Reply<T>, Error> {
        let labels: Vec<&str> = choices.iter().map(|(label, _)| label.as_str()).collect();
        let current = |initial| choices.iter().position(|&(_, value)| value == initial);
        let asked = Select::new(title, labels)
            .with_starting_cursor(initial.and_then(current).unwrap_or(0))
            .with_help_message(help)
            .with_render_config(self.render)
            .raw_prompt();

        Ok(reply(asked)?.map(|picked| choices[picked.index].1))
    }

    /// Asks a yes-or-no question, starting on `initial`.
    fn yes_or_no(&self, title: &str, initial: bool) -> Result<Reply<bool>, Error> {
        let choices = [("Yes".to_owned(), true), ("No".to_owned(), false)];

        self.select(title, &choices, Some(initial), LIST_HELP_BACK)
    }
}

impl Prompt for Terminal {
    fn device(
        &mut self,
        role: Role,
        candidates: &[&Device],
        initial: Option<usize>,
        back: bool,
    ) -> Result<Reply<usize>, Error> {
        let widths = candidates.iter().map(|device| device.name.chars().count());
        let width = widths.max().unwrap_or(0);
        let label = |device: &Device| format!("{:<width$}  {}", device.name, device.detail);
        let choices: Vec<(String, usize)> = candidates
            .iter()
            .enumerate()
            .map(|(position, device)| (label(device), position))
            .collect();
        let help = if back { LIST_HELP_BACK } else { LIST_HELP };

        self.select(&format!("{role} device"), &choices, initial, help)
    }

    fn method(
        &mut self,
        role: Role,
        family: Family,
        device: &Device,
        initial: Option<Method>,
        optional: bool,
    ) -> Result<Reply<Option<Method>>, Error> {
        let title = format!("{role} {family} configuration for {}", device.name);
        let mut choices = vec![
            (Method::Static.to_string(), Some(Method::Static)),
            (Method::Dhcp.to_string(), Some(Method::Dhcp)),
        ];
        if optional {
            choices.push(("None".to_owned(), None));
        }

        self.select(&title, &choices, Some(initial), LIST_HELP_BACK)
    }

    fn addressed(
        &mut self,
        role: Role,
        family: Family,
        device: &Device,
        initial: bool,
    ) -> Result<Reply<bool>, Error> {
        let title = format!("Set an {family} address for {role} on {}?", device.name);

        self.yes_or_no(&title, initial)
    }

    fn text<T: fmt::Display>(
        &mut self,
        role: Role,
        family: Family,
        field: Field,
        earlier: Option<T>,
        parse: impl Fn(&str) -> Result<T, Invalid> + Copy + 'static,
    ) -> Result<Reply<T>, Error> {
        let title = format!("{role} {family} {field}");
        let earlier = earlier.map(|earlier| earlier.to_string());
        let accept = move |text: &str| -> Result<Validation, CustomUserError> {
            Ok(match parse(text) {
                Ok(_) => Validation::Valid,
                Err(refused) => Validation::Invalid(refused.into()),
            })
        };

        let mut text = Text::new(&title)
            .with_validator(accept)
            .with_help_message(TEXT_HELP)
            .with_render_config(self.render);
        if let Some(example) = example(role, family, field) {
            text = text.with_placeholder(example);
        }
        if let Some(earlier) = &earlier {
            text = text.with_initial_value(earlier);
        }

        Ok(reply(text.prompt())?.map(|text| {
            parse(&text).expect("inquire submitted text its validator refused. This is a bug.")
        }))
    }

    fn dhcp_server(
        &mut self,
        role: Role,
        family: Family,
        device: &Device,
        initial: bool,
    ) -> Result<Reply<bool>, Error> {
        let title = format!(
            "Use the router as {family} DHCP server for {role} on {}?",
            device.name
        );

        self.yes_or_no(&title, initial)
    }

    fn another_lan(&mut self, available: bool, initial: bool) -> Result<Reply<bool>, Error> {
        let title = "Add another LAN device?";
        if !available {
            let choices = [("No (every device is in use)".to_owned(), false)];

            return self.select(title, &choices, None, LIST_HELP_BACK);
        }

        self.yes_or_no(title, initial)
    }
}

/// Sorts how a prompt ended into an answer, a step back, or the end of the wizard.
fn reply<T>(asked: InquireResult<T>) -> Result<Reply<T>, Error> {
    match asked {
        Ok(answer) => Ok(Reply::Answer(answer)),
        // Ctrl-D, and also Esc and Ctrl-G, which inquire does not tell apart from it.
        Err(InquireError::OperationCanceled) => Ok(Reply::Back),
        // Ctrl-C.
        Err(InquireError::OperationInterrupted) => Err(Error::Interrupted),
        Err(InquireError::NotTTY) => Err(Error::NotATerminal),
        Err(InquireError::IO(e)) => Err(Error::Io(e)),
        Err(e @ (InquireError::InvalidConfiguration(_) | InquireError::Custom(_))) => {
            panic!("inquire refused a prompt the wizard built: {e}. This is a bug.")
        }
    }
}

/// The form to type `field` in, shown while its prompt is empty; `None` for most.
fn example(role: Role, family: Family, field: Field) -> Option<&'static str> {
    match (field, role, family) {
        (Field::Cidr, Role::Wan, Family::V4) => Some("192.168.1.100/24"),
        (Field::Cidr, Role::Wan, Family::V6) => Some("2001:db8::100/64"),
        (Field::Cidr, Role::Lan(_), Family::V4) => Some("192.168.1.1/24"),
        (Field::Cidr, Role::Lan(_), Family::V6) => Some("fd00::1/64"),
        (Field::Gateway | Field::PoolStart | Field::PoolEnd, ..) => None,
    }
}
