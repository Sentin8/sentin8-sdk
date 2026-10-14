// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Shared Policy Studio RFW pages.
//!
//! Every adopting service serves the same four admin pages from its
//! `GET /v1/admin/ui/{page}` handler by calling these constructors with its
//! own colon service identity. The dash is a pure rendering host — the
//! pages are *definitions*; all data and mutations flow through the shared
//! policy-admin API this service already mounts.
//!
//! Wire contract notes:
//! - Row lists carry `id` = the policy-set name (or colon-joined tuple /
//!   attribute key) because the dash renderer substitutes ONLY `{id}` from
//!   the row's `id` field in row-action endpoints.
//! - The editor page is generated PER SET with the concrete name embedded in
//!   the native widget props — `{name}` placeholders would render literally
//!   (the renderer has no row context on a static page).
//! - Simulation evaluates SERVER-side via the dry-run endpoint
//!   (`POST /v1/admin/policy-sets/{name}/test`) — the browser never
//!   evaluates policy (fail-closed single decision point).

use crate::page::{AdminPage, AdminUiAction, AdminUiActionType};
use crate::widget::{
    ButtonType, FormFieldOption, FormFieldType, FormFieldValidation, FormMethod, RemoteWidget,
    WidgetButton, WidgetDataTable, WidgetDataTableColumn, WidgetForm, WidgetFormField,
    WidgetNative,
};

/// One column of the decision/set tables (non-sortable).
fn col(key: &str, label: &str) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable: false,
        width: None,
        format: None,
    }
}

/// One sortable column.
fn cols(key: &str, label: &str) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable: true,
        width: None,
        format: None,
    }
}

fn table_with_actions(
    columns: Vec<WidgetDataTableColumn>,
    endpoint: &str,
    row_actions: Vec<WidgetButton>,
) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("No data.".into()),
        row_link: None,
        row_actions,
    })
}

fn table(columns: Vec<WidgetDataTableColumn>, endpoint: &str) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("No data.".into()),
        row_link: None,
        row_actions: vec![],
    })
}

fn row_action_post(label: &str, endpoint: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: ButtonType::Primary,
        route: None,
        endpoint: Some(endpoint.into()),
        icon: None,
    }
}

fn row_action_danger(label: &str, endpoint: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: ButtonType::Danger,
        route: None,
        endpoint: Some(endpoint.into()),
        icon: None,
    }
}

fn form_field(
    key: &str,
    label: &str,
    field_type: FormFieldType,
    required: bool,
    placeholder: Option<&str>,
    help_text: Option<&str>,
) -> WidgetFormField {
    WidgetFormField {
        key: key.into(),
        label: label.into(),
        field_type,
        required,
        placeholder: placeholder.map(Into::into),
        default_value: None,
        options: None,
        validation: None,
        width: None,
        help_text: help_text.map(Into::into),
        visible_if: None,
    }
}

/// The shadow/enforced mode selector (§3.5: tenant-authored sets start in
/// shadow — a mistake degrades to logging, not lockout).
fn select_mode_field() -> WidgetFormField {
    WidgetFormField {
        key: "mode".into(),
        label: "Mode".into(),
        field_type: FormFieldType::Select,
        required: true,
        placeholder: None,
        default_value: Some(serde_json::json!("shadow")),
        options: Some(vec![
            FormFieldOption {
                value: "shadow".into(),
                label: "Shadow (evaluate, never block — recommended start)".into(),
            },
            FormFieldOption {
                value: "enforced".into(),
                label: "Enforced (deny blocks the request)".into(),
            },
        ]),
        validation: None,
        width: None,
        help_text: Some(
            "Shadow logs policy.would_deny but never blocks; promote to enforced deliberately after observing the decision feed (§3.4).".into(),
        ),
        visible_if: None,
    }
}

/// `policy-sets` — the list page. Row `id` = policy_set_name (the data
/// endpoint maps it), so the `{id}` aliases resolve at click time.
///
/// `service_type` — the colon identity (e.g. `sentin8:cron`); only used for
/// the page title so an admin can see WHICH service's policies they edit.
pub fn policy_sets_page(service_type: &str) -> AdminPage {
    AdminPage::new(format!("Policy Sets (Shield) — {service_type}"))
        .action(AdminUiAction {
            label: "New Policy Set".into(),
            action_type: AdminUiActionType::Link,
            route: Some("policy-sets/new".into()),
            endpoint: None,
            icon: Some("add".into()),
        })
        .widget(table_with_actions(
            vec![
                col("policy_set_name", "Policy Set"),
                cols("origin", "Origin"),
                cols("mode", "Mode"),
                cols("version", "Version"),
                cols("enabled", "Enabled"),
                cols("policies_len", "Bytes"),
            ],
            "/policy-sets",
            vec![
                row_action_post("Edit", "policy-sets/{id}/edit"),
                row_action_post("Enforce", "policy-sets/{id}/enforce"),
                row_action_post("Shadow", "policy-sets/{id}/shadow"),
                row_action_post("Disable", "policy-sets/{id}/disable"),
                row_action_danger("Delete", "policy-sets/{id}/delete"),
            ],
        ))
}

/// `policy-sets/new` — the tenant-set create form. Submits the shared
/// `POST /v1/admin/policy-sets` alias, which validates at write time (§3.1)
/// and redirects the renderer to the editor (§3.7).
pub fn policy_sets_new_page(service_type: &str) -> AdminPage {
    AdminPage::new("New Policy Set")
        .widget(RemoteWidget::Form(WidgetForm {
            fields: vec![
                WidgetFormField {
                    key: "policy_set_name".into(),
                    label: "Set Name".into(),
                    field_type: FormFieldType::Text,
                    required: true,
                    placeholder: Some(format!("e.g. tenant-{service_type}-guardrail")),
                    default_value: None,
                    options: None,
                    validation: Some(FormFieldValidation {
                        min: None,
                        max: None,
                        pattern: Some("^[A-Za-z0-9_-]{1,128}$".into()),
                        min_length: None,
                        max_length: Some(128),
                        custom_message: Some("Use 1-128 letters, digits, '-' or '_'".into()),
                    }),
                    width: None,
                    help_text: Some("Unique within this service and environment.".into()),
                    visible_if: None,
                },
                form_field("description", "Description", FormFieldType::Text, false, Some("What does this set guard?"), None),
                select_mode_field(),
                form_field(
                    "policies",
                    "Shield Policies",
                    FormFieldType::Textarea,
                    true,
                    Some(
                        "permit(principal, action == Action::\"ACTION_ID\", resource) when { principal.scopes.contains(\"SCOPE\") };",
                    ),
                    Some(
                        "One Shield statement per permit/forbid. Validated at write time — invalid text is rejected with 422 and nothing is stored (fail-closed §3.1).",
                    ),
                ),
                form_field(
                    "schema",
                    "Shield Schema (optional)",
                    FormFieldType::Textarea,
                    false,
                    Some("{\"namespace\": ...}"),
                    Some(
                        "Optional Shield policy-schema JSON; when present the set is strictly schema-validated at write time.",
                    ),
                ),
            ],
            submit_endpoint: "/v1/admin/policy-sets".into(),
            submit_label: "Create Policy Set".into(),
            cancel_label: "Cancel".into(),
            method: FormMethod::Post,
        }))
}

/// `policy-sets/{name}/edit` — the per-set editor + simulator. The set name
/// is extracted from the page path by the caller and embedded CONCRETELY in
/// the native widget props (the renderer has no row context here).
pub fn policy_edit_page(service_type: &str, set_name: &str) -> AdminPage {
    AdminPage::new("Policy Studio").widget(RemoteWidget::Native(WidgetNative {
        widget_name: "policy_simulator".into(),
        props: serde_json::json!({
            "policy_set_name": set_name,
            "save_endpoint": format!("/v1/admin/policy-sets/{set_name}/save"),
            "test_endpoint": format!("/v1/admin/policy-sets/{set_name}/test"),
            "service": service_type,
            "default_action": format!("{service_type}:read"),
        }),
        data_endpoint: Some(format!("/policy-sets/{set_name}")),
    }))
}

/// `policy-decisions` — the deny / would-deny feed (would-deny visibility,
/// §3.7). Data comes from `GET /v1/admin/policy-decisions` (the shared
/// audit-trail reader).
pub fn policy_decisions_page(service_type: &str) -> AdminPage {
    AdminPage::new(format!("Policy Decisions — {service_type}")).widget(table(
        vec![
            cols("timestamp", "Time"),
            cols("decision", "Decision"),
            cols("action_id", "Action"),
            cols("policy_set", "Policy Set"),
            cols("reason", "Reason"),
            cols("subject", "Subject"),
        ],
        "/policy-decisions",
    ))
}

/// Dispatch a `policy-*` admin-UI page request against the shared page
/// constructors. Returns `None` for non-policy pages so the service's own
/// match arm handles them.
///
/// The editor route shape is `policy-sets/{name}/edit` — the set name is the
/// path suffix, so pages are generated per set at request time.
pub fn policy_page(service_type: &str, page: &str) -> Option<AdminPage> {
    match page {
        "policy-sets" => Some(policy_sets_page(service_type)),
        "policy-sets/new" => Some(policy_sets_new_page(service_type)),
        "policy-decisions" => Some(policy_decisions_page(service_type)),
        p if p.starts_with("policy-sets/") && p.ends_with("/edit") => {
            let name = p
                .strip_prefix("policy-sets/")
                .and_then(|r| r.strip_suffix("/edit"))
                .unwrap_or("");
            if name.is_empty() || name.contains('/') {
                return None;
            }
            Some(policy_edit_page(service_type, name))
        }
        _ => None,
    }
}
