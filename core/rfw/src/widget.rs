// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! RFW widget types - the declarative widget tree that services return.
//!
//! The Sentin8:Dash Flutter RFW runtime inflates these into native Flutter
//! widgets. Every widget type is a plain serializable struct; the renderer
//! has no knowledge of any service.

#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

// ── Top-level enum ──

/// A single node in the remote widget tree.
///
/// The type is recursive (containers hold child trees), so [`ToSchema`]
/// is implemented manually as a one-of of the variant schemas - the
/// generated component terminates recursion via `$ref` inside the
/// variants' own schemas.
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
    /// A native widget host - the dash renders a built-in Flutter widget.
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
#[derive(ToSchema, Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    ///
    /// `no_recursion` keeps the derive from forwarding the reference
    /// collection back into [`RemoteWidget`]'s manual `ToSchema::schemas` -
    /// recursion terminates at the `$ref` (see the RemoteWidget schema impl).
    #[schema(no_recursion)]
    pub children: Vec<RemoteWidget>,
}

/// Layout direction for a container's children.
#[derive(ToSchema, Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
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
#[derive(ToSchema, Debug, Clone, Serialize, Deserialize, PartialEq)]
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
#[derive(ToSchema, Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
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
#[derive(ToSchema, Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
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
#[derive(ToSchema, Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    /// Optional row click action - navigates to this route with `{row.id}` substitution.
    #[serde(default)]
    pub row_link: Option<String>,
    /// Per-row action buttons. Each button's route/endpoint supports `{row.id}` substitution.
    #[serde(default)]
    pub row_actions: Vec<WidgetButton>,
}

/// One column of a [`WidgetDataTable`].
#[derive(ToSchema, Debug, Clone, Serialize, Deserialize, PartialEq)]
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
#[derive(ToSchema, Debug, Clone, Serialize, Deserialize, PartialEq)]
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

#[derive(ToSchema, Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
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
#[derive(ToSchema, Debug, Clone, Serialize, Deserialize, PartialEq)]
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
#[derive(ToSchema, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FieldCondition {
    /// The key of the field whose value to check.
    pub field: String,
    /// The value that must match for this field to be visible.
    pub equals: serde_json::Value,
}

#[derive(ToSchema, Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
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
#[derive(ToSchema, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FormFieldOption {
    /// The submitted value.
    pub value: String,
    /// The displayed label.
    pub label: String,
}

/// Validation constraints for a form field.
#[derive(ToSchema, Debug, Clone, Serialize, Deserialize, PartialEq)]
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
#[derive(ToSchema, Debug, Clone, Serialize, Deserialize, PartialEq)]
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
#[derive(ToSchema, Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
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
#[derive(ToSchema, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WidgetCard {
    /// Card title.
    #[serde(default)]
    pub title: Option<String>,
    /// Card subtitle.
    #[serde(default)]
    pub subtitle: Option<String>,
    /// Card body widgets (`no_recursion` - see [`RemoteWidget`]).
    #[serde(default)]
    #[schema(no_recursion)]
    pub children: Vec<RemoteWidget>,
    /// Buttons rendered in the card footer/header.
    #[serde(default)]
    pub actions: Vec<WidgetButton>,
}

// ── Chart ──

/// A simple chart backed by a data endpoint.
#[derive(ToSchema, Debug, Clone, Serialize, Deserialize, PartialEq)]
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

#[derive(ToSchema, Debug, Clone, Serialize, Deserialize, PartialEq)]
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

/// A native widget host - the dash renders a built-in Flutter widget.
#[derive(ToSchema, Debug, Clone, Serialize, Deserialize, PartialEq)]
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
#[derive(ToSchema, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WidgetRow {
    /// Child widgets (`no_recursion` - see [`RemoteWidget`]).
    #[schema(no_recursion)]
    pub children: Vec<RemoteWidget>,
    /// Gap between children.
    #[serde(default)]
    pub spacing: f64,
}

/// A vertical layout column.
#[derive(ToSchema, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WidgetColumn {
    /// Child widgets (`no_recursion` - see [`RemoteWidget`]).
    #[schema(no_recursion)]
    pub children: Vec<RemoteWidget>,
    /// Gap between children.
    #[serde(default)]
    pub spacing: f64,
}

/// An empty gap.
#[derive(ToSchema, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WidgetSpacer {
    /// Gap size in logical pixels.
    #[serde(default)]
    pub size: f64,
}

// ── Manual recursion-breaking schema ─────────────────────────────────────
// `RemoteWidget` is a recursive tree (WidgetContainer.children, WidgetCard,
// WidgetRow, WidgetColumn). A ToSchema derive inlines the full variant tree
// at every recursion level and the utoipa generator recurses forever, so the
// impl is hand-written here (DESIGN.md §3.2, "Recursive widget tree"):
//
// - `PartialSchema::schema()` emits a `OneOf` of the variant objects. Each
//   item carries the serde internal tag (`"type": "<variant>"`, lowercase)
//   plus the variant struct's own properties inlined - exactly the shape the
//   derive produces for an internally-tagged enum - so the component body is
//   a genuine union, never a bare self-`$ref` (a degenerate
//   `{"$ref": "#/components/schemas/RemoteWidget"}` body breaks redocly's
//   bundler with "Self-referencing circular pointer" and silently skips
//   site doc generation for every unit carrying RFW pages).
// - `ToSchema::schemas()` registers the variant structs so their `$ref`-able
//   components exist alongside the union.
// - Recursion terminates through property `$$ref`s: variant structs keep
//   their `children: Vec<RemoteWidget>` references, which resolve against
//   this same component without re-inlining it.
impl utoipa::PartialSchema for RemoteWidget {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        use utoipa::openapi::schema::{Schema, SchemaType};
        use utoipa::openapi::OneOfBuilder;

        /// The internal tag property schema: a single-constant string enum
        /// (`serde(tag = "type")` variant discriminator).
        fn tag_schema(tag: &'static str) -> Schema {
            Schema::Object(
                utoipa::openapi::schema::ObjectBuilder::new()
                    .schema_type(SchemaType::Type(utoipa::openapi::schema::Type::String))
                    .enum_values(Some([tag]))
                    .build(),
            )
        }

        /// Flatten the variant struct's object schema into a tagged oneOf
        /// item - the derive-equivalent internally-tagged newtype shape.
        fn tagged_item(
            tag: &'static str,
            item: utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>,
        ) -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
            let mut builder = utoipa::openapi::schema::ObjectBuilder::new()
                .property("type", tag_schema(tag))
                .required("type");
            match item {
                utoipa::openapi::RefOr::T(Schema::Object(obj)) => {
                    for (name, prop) in obj.properties.iter() {
                        builder = builder.property(name.clone(), prop.clone());
                    }
                    for req in &obj.required {
                        builder = builder.required(req.clone());
                    }
                    builder.into()
                }
                // Non-object variant schema (currently impossible - every
                // variant is a derived struct): carry it untagged.
                other => other,
            }
        }

        let one_of = OneOfBuilder::new()
            .item(tagged_item("container", WidgetContainer::schema()))
            .item(tagged_item("text", WidgetText::schema()))
            .item(tagged_item("data_table", WidgetDataTable::schema()))
            .item(tagged_item("form", WidgetForm::schema()))
            .item(tagged_item("button", WidgetButton::schema()))
            .item(tagged_item("card", WidgetCard::schema()))
            .item(tagged_item("chart", WidgetChart::schema()))
            .item(tagged_item("native", WidgetNative::schema()))
            .item(tagged_item("row", WidgetRow::schema()))
            .item(tagged_item("column", WidgetColumn::schema()))
            .item(tagged_item("spacer", WidgetSpacer::schema()))
            .build();
        utoipa::openapi::RefOr::T(Schema::OneOf(one_of))
    }
}

impl utoipa::ToSchema for RemoteWidget {
    fn name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("RemoteWidget")
    }

    /// Register the variant structs reachable from the union so their
    /// components are emitted alongside `RemoteWidget`.
    fn schemas(
        schemas: &mut Vec<(
            String,
            utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>,
        )>,
    ) {
        use utoipa::{PartialSchema, ToSchema};
        macro_rules! push_variant {
            ($v:ty) => {{
                schemas.push((
                    <$v as ToSchema>::name().into_owned(),
                    <$v as PartialSchema>::schema(),
                ));
                <$v as ToSchema>::schemas(schemas);
            }};
        }
        // Each variant struct pulls in its own field types (ContainerDirection,
        // WidgetDataTableColumn, FormFieldType, ...) - their components must be
        // registered for the inline `$ref`s in the oneOf items to resolve.
        // Variant `children` references resolve against the RemoteWidget
        // component itself.
        push_variant!(WidgetContainer);
        push_variant!(WidgetText);
        push_variant!(WidgetDataTable);
        push_variant!(WidgetForm);
        push_variant!(WidgetButton);
        push_variant!(WidgetCard);
        push_variant!(WidgetChart);
        push_variant!(WidgetNative);
        push_variant!(WidgetRow);
        push_variant!(WidgetColumn);
        push_variant!(WidgetSpacer);
    }
}
