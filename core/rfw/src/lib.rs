// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! sentin8-rfw — Remote Flutter Widget (RFW) types for service-owned admin UI.
//!
//! Every service that provides admin UI exposes RFW definitions via
//! `GET /v1/admin/ui/{page}`. The Sentin8:Dash fetches these at runtime,
//! inflates them into native Flutter widgets, and proxies form submissions
//! back to the service via `POST /v1/admin/{resource}`.
//!
//! The renderer supports POST for admin mutations; services expose POST
//! alias routes for update/delete operations. Icons are Material Icons
//! code points (hex strings), never names.

#![deny(missing_docs)]

pub mod page;
pub mod policy_pages;
pub mod response;
pub mod widget;

pub use page::{AdminPage, AdminUiAction, AdminUiActionType, AdminUiPage};
pub use policy_pages::policy_page;
pub use response::AdminUiResponse;
pub use widget::{
    FormFieldOption, FormFieldValidation, RemoteWidget, WidgetButton, WidgetCard, WidgetChart,
    WidgetContainer, WidgetDataTable, WidgetDataTableColumn, WidgetForm, WidgetFormField,
    WidgetNative, WidgetText, WidgetTextType,
};

// Wire-contract tests — what every service's `GET /v1/admin/ui/{page}`
// must produce for the dash RFW renderer.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page::{AdminUiAction, AdminUiActionType, AdminUiPage};
    use crate::response::FieldError;
    use crate::widget::{
        ButtonType, ChartType, ContainerDirection, FieldCondition, FormFieldOption, FormFieldType,
        FormFieldValidation, FormMethod, TextAlign, WidgetDataTableColumn, WidgetFormField,
        WidgetNative, WidgetTextType,
    };
    use serde_json::json;

    fn sample_page() -> AdminUiPage {
        AdminPage::new("Accounts")
            .widget(RemoteWidget::Text(WidgetText {
                text: "All accounts".into(),
                text_type: WidgetTextType::Heading,
                align: TextAlign::Left,
                max_lines: Some(2),
            }))
            .widget(RemoteWidget::DataTable(WidgetDataTable {
                columns: vec![WidgetDataTableColumn {
                    key: "iban".into(),
                    label: "IBAN".into(),
                    sortable: true,
                    width: Some(240.0),
                    format: Some("iban".into()),
                }],
                data_endpoint: "/accounts".into(),
                sortable: true,
                filterable: true,
                page_size: 25,
                empty_message: Some("No accounts".into()),
                row_link: Some("/accounts/{row.id}".into()),
                row_actions: vec![WidgetButton {
                    label: "Freeze".into(),
                    button_type: ButtonType::Danger,
                    route: None,
                    endpoint: Some("/accounts/{row.id}/freeze".into()),
                    icon: None,
                }],
            }))
            .action(AdminUiAction {
                label: "New account".into(),
                action_type: AdminUiActionType::Submit,
                route: None,
                endpoint: Some("/accounts".into()),
                icon: Some("e91b".into()),
            })
            .build()
    }

    #[test]
    fn admin_page_roundtrip() {
        let page = sample_page();
        let v = serde_json::to_value(&page).unwrap();
        assert_eq!(v["title"], "Accounts");
        assert_eq!(v["widgets"][0]["type"], "Text");
        assert_eq!(v["widgets"][1]["type"], "DataTable");
        let back: AdminUiPage = serde_json::from_value(v).unwrap();
        assert_eq!(back, page);
    }

    #[test]
    fn data_table_endpoint_is_admin_relative() {
        // data_endpoint is relative to /v1/admin/.
        let page = sample_page();
        let v = serde_json::to_value(&page).unwrap();
        let ep = v["widgets"][1]["data_endpoint"].as_str().unwrap();
        assert!(ep.starts_with('/'), "endpoint {ep} must be admin-relative");
        assert!(
            !ep.contains("/v1/admin/"),
            "prefix is implied, not embedded"
        );
    }

    #[test]
    fn icon_is_material_codepoint_hex_string() {
        // Icons are Material Icons code points (hex strings), not names.
        let page = sample_page();
        let v = serde_json::to_value(&page).unwrap();
        let icon = v["actions"][0]["icon"].as_str().unwrap();
        assert!(
            icon.chars().all(|c| c.is_ascii_hexdigit()),
            "icon must be a hex code point string, got {icon}"
        );
    }

    #[test]
    fn tagged_enum_wire_names() {
        // serde tag = "type" with default (PascalCase) variant names — the
        // dash RFW runtime dispatches on these exact strings.
        let w = RemoteWidget::Card(WidgetCard {
            title: Some("Balances".into()),
            subtitle: None,
            children: vec![],
            actions: vec![],
        });
        let v = serde_json::to_value(&w).unwrap();
        assert_eq!(v["type"], "Card");
        let w2 = RemoteWidget::Chart(WidgetChart {
            chart_type: ChartType::Line,
            data_endpoint: "/balances/history".into(),
            title: None,
            height: Some(320.0),
        });
        assert_eq!(serde_json::to_value(&w2).unwrap()["type"], "Chart");
        // Inner enums are snake_case/lowercase (renamed explicitly).
        assert_eq!(
            serde_json::to_value(ChartType::Line).unwrap(),
            json!("line")
        );
    }

    #[test]
    fn enums_snake_case_on_the_wire() {
        assert_eq!(
            serde_json::to_value(AdminUiActionType::Submit).unwrap(),
            json!("submit")
        );
        assert_eq!(
            serde_json::to_value(AdminUiActionType::Dialog).unwrap(),
            json!("dialog")
        );
        assert_eq!(
            serde_json::to_value(ButtonType::Danger).unwrap(),
            json!("danger")
        );
        assert_eq!(
            serde_json::to_value(FormFieldType::DateTime).unwrap(),
            json!("date_time")
        );
        assert_eq!(serde_json::to_value(FormMethod::Put).unwrap(), json!("put"));
        assert_eq!(
            serde_json::to_value(ContainerDirection::Horizontal).unwrap(),
            json!("horizontal")
        );
        assert_eq!(
            serde_json::to_value(TextAlign::Center).unwrap(),
            json!("center")
        );
        assert_eq!(
            serde_json::to_value(WidgetTextType::Subheading).unwrap(),
            json!("subheading")
        );
        assert_eq!(serde_json::to_value(ChartType::Bar).unwrap(), json!("bar"));
    }

    #[test]
    fn form_field_conditional_visibility_roundtrip() {
        let f = WidgetFormField {
            key: "provider_id".into(),
            label: "Provider".into(),
            field_type: FormFieldType::Select,
            required: true,
            placeholder: None,
            default_value: None,
            options: Some(vec![FormFieldOption {
                value: "fdx-1".into(),
                label: "FDX One".into(),
            }]),
            validation: Some(FormFieldValidation {
                min: Some(0.0),
                max: Some(100.0),
                pattern: None,
                min_length: None,
                max_length: None,
                custom_message: Some("must be 0-100".into()),
            }),
            width: None,
            help_text: Some("Choose a provider".into()),
            visible_if: Some(FieldCondition {
                field: "auth_mode".into(),
                equals: json!("staff"),
            }),
        };
        let form = RemoteWidget::Form(WidgetForm {
            fields: vec![f],
            submit_endpoint: "/providers".into(),
            submit_label: "Save".into(),
            cancel_label: "Cancel".into(),
            method: FormMethod::Post,
        });
        let v = serde_json::to_value(&form).unwrap();
        let field = &v["fields"][0];
        assert_eq!(field["visible_if"]["field"], "auth_mode");
        assert_eq!(field["visible_if"]["equals"], "staff");
        let back: RemoteWidget = serde_json::from_value(v).unwrap();
        assert_eq!(back, form);
    }

    #[test]
    fn response_envelope_variants() {
        let page_resp = AdminUiResponse::page(sample_page());
        let v = serde_json::to_value(&page_resp).unwrap();
        assert_eq!(v["response_type"], "page");
        assert!(v.get("page").is_some());
        let back: AdminUiResponse = serde_json::from_value(v).unwrap();
        assert_eq!(back, page_resp);

        let redirect = AdminUiResponse::redirect("/accounts/42");
        let v = serde_json::to_value(&redirect).unwrap();
        assert_eq!(v["response_type"], "redirect");
        assert_eq!(v["route"], "/accounts/42");

        let err = AdminUiResponse::validation_error(
            "invalid request",
            vec![FieldError {
                field: "iban".into(),
                message: "bad checksum".into(),
            }],
        );
        let v = serde_json::to_value(&err).unwrap();
        assert_eq!(v["response_type"], "error");
        assert_eq!(v["field_errors"][0]["field"], "iban");
        let back: AdminUiResponse = serde_json::from_value(v).unwrap();
        assert_eq!(back, err);
    }

    #[test]
    fn native_widget_props_roundtrip() {
        let n = RemoteWidget::Native(WidgetNative {
            widget_name: "payment_simulator".into(),
            props: json!({"instruction_id": "i-1"}),
            data_endpoint: Some("/payment-instructions".into()),
        });
        let v = serde_json::to_value(&n).unwrap();
        assert_eq!(v["widget_name"], "payment_simulator");
        let back: RemoteWidget = serde_json::from_value(v).unwrap();
        assert_eq!(back, n);
    }
}
