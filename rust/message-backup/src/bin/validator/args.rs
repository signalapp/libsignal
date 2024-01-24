//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

pub(crate) enum ParseVerbosity {
    None,
    PrintOneLine,
    PrintPretty,
}

fn print_oneline(message: &dyn std::fmt::Debug) {
    eprintln!("{message:?}")
}

fn print_pretty(message: &dyn std::fmt::Debug) {
    eprintln!("{message:#?}")
}

impl ParseVerbosity {
    pub(crate) fn into_visitor(self) -> Option<fn(&dyn std::fmt::Debug)> {
        match self {
            ParseVerbosity::None => None,
            ParseVerbosity::PrintOneLine => Some(print_oneline),
            ParseVerbosity::PrintPretty => Some(print_pretty),
        }
    }
}

impl From<u8> for ParseVerbosity {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::PrintOneLine,
            2.. => Self::PrintPretty,
        }
    }
}
