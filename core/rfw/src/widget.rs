// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! RFW widget types — the declarative widget tree that services return.
//!
//! The Sentin8:Dash Flutter RFW runtime inflates these into native Flutter
//! widgets. Every widget type is a plain serializable struct; the renderer
//! has no knowledge of any service.

#![deny(missing_docs)]

use serde::{Deserialize, Serialize};

// ── Top-level enum ──

/// A single node in the remote widget tree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum RemoteWidget {
    /// A vertical or horizontal container holding child widgets.
    Container(WidgetContainer),
    /// A text label with optional styling.
    Text(WidgetText),
    /// A data table with columns, rows, sort/filter/paginate.
    DataTable(WidgetDataTable),
    /// A form with fields and a submit action.
    Form(WidgetForm),
    /// A button (submit, cancel, or link).
    Button(WidgetButton),
    /// A card panel (glass panel with optional title + children).
    Card(WidgetCard),
    /// A simple chart (bar or line).
    Chart(WidgetChart),
    /// A native widget host — the dash renders a built-in Flutter widget.
    Native(WidgetNative),
    /// A row of child widgets laid out horizontally.
    Row(WidgetRow),
    /// A column of child widgets laid out vertically with spacing.
    Column(WidgetColumn),
    /// A spacer (empty gap).
    Spacer(WidgetSpacer),
}

// ── Container ──

/// A scrollable container with layout direction and padding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WidgetContainer {
    /// Layout direction of the children.
    #[serde(default)]
    pub direction: ContainerDirection,
    /// Gap between children.
    #[serde(default)]
    pub spacing: f64,
    /// Outer padding.
    #[serde(default)]
    pub padding: f64,
    /// Child widgets.
    pub children: Vec<RemoteWidget>,
}

/// Layout direction for a container's children.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ContainerDirection {
    /// Stack children vertically (default).
    #[default]
    Vertical,
    /// Lay children out horizontally.
    Horizontal,
}

// ── Text ──

/// A text label with optional styling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WidgetText {
    /// The text content.
    pub text: String,
    /// Style variant.
    #[serde(default)]
    pub text_type: WidgetTextType,
    /// Text alignment.
    #[serde(default)]
    pub align: TextAlign,
    /// Maximum lines before ellipsis.
    #[serde(default)]
    pub max_lines: Option<u32>,
}

/// Text style variant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum WidgetTextType {
    /// Default body text.
    #[default]
    Body,
    /// Large heading.
    Heading,
    /// Medium heading.
    Subheading,
    /// Small caption.
    Caption,
    /// Form/control label.
    Label,
    /// Page title.
    Title,
}

/// Text alignment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TextAlign {
    /// Left-aligned (default).
    #[default]
    Left,
    /// Centered.
    Center,
    /// Right-aligned.
    Right,
}

// ── DataTable ──

/// A data table with server-side rows, sorting, filtering, and pagination.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WidgetDataTable {
    /// Column definitions.
    pub columns: Vec<WidgetDataTableColumn>,
    /// The data endpoint to fetch rows (relative to the service's `/v1/admin/` prefix).
    /// E.g. `"/accounts"` → `GET /v1/admin/accounts`.
    pub data_endpoint: String,
    /// Whether column sorting is enabled.
    #[serde(default)]
    pub sortable: bool,
    /// Whether column filtering is enabled.
    #[serde(default)]
    pub filterable: bool,
    /// Rows per page (0 = renderer default).
    #[serde(default)]
    pub page_size: u32,
    /// Message shown when there are no rows.
    #[serde(default)]
    pub empty_message: Option<String>,
    /// Optional row click action — navigates to this route with `{row.id}` substitution.
    #[serde(default)]
    pub row_link: Option<String>,
    /// Per-row action buttons. Each button's route/endpoint supports `{row.id}` substitution.
    #[serde(default)]
    pub row_actions: Vec<WidgetButton>,
}

/// One column of a [`WidgetDataTable`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WidgetDataTableColumn {
    /// Row-data key for this column.
    pub key: String,
    /// Column header label.
    pub label: String,
    /// Whether this column sorts.
    #[serde(default)]
    pub sortable: bool,
    /// Fixed width in logical pixels.
    #[serde(default)]
    pub width: Option<f64>,
    /// Formatter hint (e.g. `iban`, `currency`, `datetime`).
    #[serde(default)]
    pub format: Option<String>,
}

// ── Form ──

/// A form with fields and a submit action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WidgetForm {
    /// Form fields in render order.
    pub fields: Vec<WidgetFormField>,
    /// The endpoint to POST the form data to (relative to `/v1/admin/`).
    /// E.g. `"/accounts"` → `POST /v1/admin/accounts`.
    pub submit_endpoint: String,
    /// Submit button label.
    #[serde(default)]
    pub submit_label: String,
    /// Cancel button label.
    #[serde(default)]
    pub cancel_label: String,
    /// HTTP method for submission.
    #[serde(default)]
    pub method: FormMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
/// HTTP method used for form submission.
#[serde(rename_all = "lowercase")]
pub enum FormMethod {
    /// POST submission (default).
    #[default]
    Post,
    /// PUT submission (full update).
    Put,
}

/// One input field of a [`WidgetForm`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WidgetFormField {
    /// Field key in the submitted payload.
    pub key: String,
    /// Display label.
    pub label: String,
    /// Input widget type.
    #[serde(default)]
    pub field_type: FormFieldType,
    /// Whether submission fails without a value.
    #[serde(default)]
    pub required: bool,
    /// Hint shown inside the empty field.
    #[serde(default)]
    pub placeholder: Option<String>,
    /// Initial value.
    #[serde(default)]
    pub default_value: Option<serde_json::Value>,
    /// Choices for select-type fields.
    #[serde(default)]
    pub options: Option<Vec<FormFieldOption>>,
    /// Validation constraints.
    #[serde(default)]
    pub validation: Option<FormFieldValidation>,
    /// Width in logical pixels.
    #[serde(default)]
    pub width: Option<f64>,
    /// Helper text shown below the field.
    #[serde(default)]
    pub help_text: Option<String>,
    /// Conditional visibility: only show this field when another field
    /// matches a value. Example: `{"field": "auth_mode", "equals": "staff"}`
    #[serde(default)]
    pub visible_if: Option<FieldCondition>,
}

/// A visibility condition for a form field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FieldCondition {
    /// The key of the field whose value to check.
    pub field: String,
    /// The value that must match for this field to be visible.
    pub equals: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
/// Input widget type for a form field.
#[serde(rename_all = "snake_case")]
pub enum FormFieldType {
    /// Single-line text (default).
    #[default]
    Text,
    /// Email input with validation.
    Email,
    /// Masked password input.
    Password,
    /// Integer input.
    Number,
    /// High-precision decimal input (money-safe).
    Decimal,
    /// Date picker.
    Date,
    /// Date + time picker.
    DateTime,
    /// Single-select dropdown.
    Select,
    /// Multi-select.
    Multiselect,
    /// Type-ahead search.
    Autocomplete,
    /// Boolean checkbox.
    Checkbox,
    /// Boolean switch.
    Toggle,
    /// Multi-line text.
    Textarea,
    /// File upload.
    File,
    /// Not rendered; value submitted as-is.
    Hidden,
    /// Editable key/value pair list.
    KeyValue,
}

/// One choice of a select-type form field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FormFieldOption {
    /// The submitted value.
    pub value: String,
    /// The displayed label.
    pub label: String,
}

/// Validation constraints for a form field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FormFieldValidation {
    /// Minimum numeric value.
    #[serde(default)]
    pub min: Option<f64>,
    /// Maximum numeric value.
    #[serde(default)]
    pub max: Option<f64>,
    /// Regex pattern the value must match.
    #[serde(default)]
    pub pattern: Option<String>,
    /// Minimum string length.
    #[serde(default)]
    pub min_length: Option<u32>,
    /// Maximum string length.
    #[serde(default)]
    pub max_length: Option<u32>,
    /// Message overriding the default validation error.
    #[serde(default)]
    pub custom_message: Option<String>,
}

// ── Button ──

/// A button (submit, cancel, row action, or link).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WidgetButton {
    /// Button label.
    pub label: String,
    /// Visual/emphasis style.
    #[serde(default)]
    pub button_type: ButtonType,
    /// Route to navigate to (for link buttons). Supports `{param}` substitution.
    #[serde(default)]
    pub route: Option<String>,
    /// Endpoint to POST to (for action buttons, relative to `/v1/admin/`).
    /// Endpoint to POST to (for action buttons, relative to `/v1/admin/`).
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Material Icons code point (hex string).
    #[serde(default)]
    pub icon: Option<String>,
}

/// Button visual style.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ButtonType {
    /// Filled primary button (default).
    #[default]
    Primary,
    /// Secondary/outlined button.
    Secondary,
    /// Destructive action.
    Danger,
    /// Borderless low-emphasis action.
    Ghost,
    /// Link-styled action.
    Link,
}

// ── Card ──

/// A glass card panel with optional title and children.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WidgetCard {
    /// Card title.
    #[serde(default)]
    pub title: Option<String>,
    /// Card subtitle.
    #[serde(default)]
    pub subtitle: Option<String>,
    /// Card body widgets.
    #[serde(default)]
    pub children: Vec<RemoteWidget>,
    /// Buttons rendered in the card footer/header.
    #[serde(default)]
    pub actions: Vec<WidgetButton>,
}

// ── Chart ──

/// A simple chart backed by a data endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WidgetChart {
    /// The chart kind.
    pub chart_type: ChartType,
    /// Endpoint that returns the chart series data.
    pub data_endpoint: String,
    /// Chart title.
    #[serde(default)]
    pub title: Option<String>,
    /// Height in logical pixels.
    #[serde(default)]
    pub height: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// Chart kind.
#[serde(rename_all = "lowercase")]
pub enum ChartType {
    /// Bar chart.
    Bar,
    /// Line chart.
    Line,
    /// Pie chart.
    Pie,
}

// ── Native widget host ──

/// A native widget host — the dash renders a built-in Flutter widget.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WidgetNative {
    /// The native widget name the dash recognizes.
    /// Built-in hosts: `posting_console`, `payment_simulator`, `workflow_visualizer`.
    pub widget_name: String,
    /// Props passed to the native widget (service-specific).
    #[serde(default)]
    pub props: serde_json::Value,
    /// The data endpoint the native widget calls.
    #[serde(default)]
    pub data_endpoint: Option<String>,
}

// ── Row / Column / Spacer ──

/// A horizontal layout row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WidgetRow {
    /// Child widgets.
    pub children: Vec<RemoteWidget>,
    /// Gap between children.
    #[serde(default)]
    pub spacing: f64,
}

/// A vertical layout column.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WidgetColumn {
    /// Child widgets.
    pub children: Vec<RemoteWidget>,
    /// Gap between children.
    #[serde(default)]
    pub spacing: f64,
}

/// An empty gap.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WidgetSpacer {
    /// Gap size in logical pixels.
    #[serde(default)]
    pub size: f64,
}
