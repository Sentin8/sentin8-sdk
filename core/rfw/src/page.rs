// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! RFW page definitions — the top-level structure returned by `GET /v1/admin/ui/{page}`.

use crate::widget::RemoteWidget;
use serde::{Deserialize, Serialize};

/// A complete admin UI page definition returned by `GET /v1/admin/ui/{page}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdminUiPage {
    /// The page title (shown in breadcrumb and header).
    pub title: String,
    /// The root widget tree.
    pub widgets: Vec<RemoteWidget>,
    /// Optional actions shown in the page header (buttons).
    #[serde(default)]
    pub actions: Vec<AdminUiAction>,
}

/// An action button shown in the page header.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdminUiAction {
    /// Button label.
    pub label: String,
    /// The action kind (link / submit / dialog).
    pub action_type: AdminUiActionType,
    /// Route to navigate to (for link actions).
    #[serde(default)]
    pub route: Option<String>,
    /// Endpoint to POST to (for submit actions).
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Material Icons code point (hex string) for the button.
    #[serde(default)]
    pub icon: Option<String>,
}

/// The kind of a header action button.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AdminUiActionType {
    /// Navigate to another route.
    #[default]
    Link,
    /// POST to an endpoint.
    Submit,
    /// Open a dialog.
    Dialog,
}

/// A convenience builder for constructing admin pages.
#[derive(Debug, Clone)]
pub struct AdminPage {
    title: String,
    widgets: Vec<RemoteWidget>,
    actions: Vec<AdminUiAction>,
}

impl AdminPage {
    /// Start a page with a title.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            widgets: Vec::new(),
            actions: Vec::new(),
        }
    }

    /// Append one widget.
    pub fn widget(mut self, widget: RemoteWidget) -> Self {
        self.widgets.push(widget);
        self
    }

    /// Replace the widget list.
    pub fn widgets(mut self, widgets: Vec<RemoteWidget>) -> Self {
        self.widgets = widgets;
        self
    }

    /// Append one header action.
    pub fn action(mut self, action: AdminUiAction) -> Self {
        self.actions.push(action);
        self
    }

    /// Build the final page definition.
    pub fn build(self) -> AdminUiPage {
        AdminUiPage {
            title: self.title,
            widgets: self.widgets,
            actions: self.actions,
        }
    }
}
