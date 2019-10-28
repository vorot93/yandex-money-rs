use bigdecimal::BigDecimal;
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fmt::{Debug, Display},
    str::FromStr,
};
use strum::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessScope {
    #[serde(rename = "account-info")]
    AccountInfo,
    #[serde(rename = "operation-history")]
    OperationHistory,
    #[serde(rename = "payment-p2p")]
    PaymentP2P,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenExchangeData {
    pub access_token: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    Anonymous,
    Named,
    Identified,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountType {
    Personal,
    Professional,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BalanceDetails {
    pub total: BigDecimal,
    pub available: BigDecimal,
    pub deposition_pending: BigDecimal,
    pub blocked: BigDecimal,
    pub debt: BigDecimal,
    pub hold: BigDecimal,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum CardType {
    VISA,
    MasterCard,
    AmericanExpress,
    JCB,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LinkedCard {
    #[serde(default)]
    pub pan_fragment: Option<String>,
    #[serde(default, rename = "type")]
    pub card_type: Option<CardType>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountInfo {
    pub account: String,
    pub balance: BigDecimal,
    pub currency: String,
    pub account_status: AccountStatus,
    pub account_type: AccountType,
    #[serde(default)]
    pub balance_details: Option<BalanceDetails>,
    pub cards_linked: Vec<LinkedCard>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StringNumber<T>(#[serde(with = "serde_with::rust::display_fromstr")] pub T)
where
    T: Display + FromStr,
    T::Err: Display;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationHistoryResponse {
    pub next_record: Option<StringNumber<u64>>,
    pub operations: Vec<Operation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReqOperationType {
    Deposition,
    Payment,
    IncomingTransfersUnaccepted,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RspOperationType {
    PaymentShop,
    OutgoingTransfer,
    Deposition,
    IncomingTransfer,
    IncomingTransferProtected,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Success,
    Refused,
    InProgress,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferDirection {
    In,
    Out,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Operation {
    pub operation_id: String,
    pub status: OperationStatus,
    pub datetime: DateTime<Utc>,
    pub title: String,
    pub pattern_id: Option<String>,
    pub direction: TransferDirection,
    pub amount: BigDecimal,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(rename = "type")]
    pub operation_type: RspOperationType,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipientType {
    Account,
    Phone,
    Email,
}

#[derive(Clone, Debug)]
pub enum UserId {
    Account(u64),
    Phone(phonenumber::PhoneNumber),
    Email(String),
}

impl Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Account(id) => write!(f, "{}", id),
            Self::Phone(number) => write!(f, "{}", number),
            Self::Email(addr) => write!(f, "{}", addr),
        }
    }
}

#[derive(Clone, Debug)]
pub enum RequestAmount {
    Total(BigDecimal),
    Net(BigDecimal),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationDetails {
    pub operation_id: String,
    pub status: OperationStatus,
    #[serde(default)]
    pub pattern_id: Option<String>,
    pub direction: TransferDirection,
    pub amount: BigDecimal,
    #[serde(default)]
    pub amount_due: Option<BigDecimal>,
    #[serde(default)]
    pub fee: Option<BigDecimal>,
    pub datetime: DateTime<Utc>,
    pub title: String,
    #[serde(default)]
    pub sender: Option<String>,
    #[serde(default)]
    pub recipient: Option<String>,
    #[serde(default)]
    pub recipient_type: Option<RecipientType>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub codepro: Option<bool>,
    #[serde(default)]
    pub protection_code: Option<String>,
    #[serde(default)]
    pub expires: Option<DateTime<Utc>>,
    #[serde(default)]
    pub answer_datetime: Option<DateTime<Utc>>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub details: Option<String>,
    pub operation_type: RspOperationType,
    #[serde(default)]
    pub digital_goods: Option<String>,
}

#[derive(Clone, Debug)]
pub enum TestCard {
    Available,
    Custom(String),
}

#[derive(Clone, Debug)]
pub enum TestResult {
    Success,
    Other(String),
}

#[derive(Clone, Debug, Deserialize)]
pub struct WalletSource {
    pub allowed: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CardSource {
    pub id: String,
    #[serde(flatten)]
    pub data: LinkedCard,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CardsSource {
    allowed: bool,
    csc_required: Option<bool>,
    items: Option<Vec<CardSource>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct MoneySources {
    pub wallet: WalletSource,
    pub cards: CardsSource,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RequestPaymentSuccessData {
    pub balance: BigDecimal,
    pub request_id: String,
    pub money_source: MoneySources,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RequestPaymentResponse {
    Success(RequestPaymentSuccessData),
    HoldForPickup(RequestPaymentSuccessData),
    Refused { error: String },
}

impl RequestPaymentResponse {
    #[allow(clippy::missing_errors_doc)]
    pub fn into_result(self) -> Result<(bool, RequestPaymentSuccessData), String> {
        match self {
            Self::Success(data) => Ok((false, data)),
            Self::HoldForPickup(data) => Ok((true, data)),
            Self::Refused { error } => Err(error),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Secure3DData {
    pub ext_auth_success_uri: String,
    pub ext_auth_fail_uri: String,
}

#[derive(Clone, Debug, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum ProcessPaymentMoneySource {
    Wallet,
    Card {
        id: String,
        secure3d: Option<Secure3DData>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessPaymentSuccessData {
    pub payment_id: String,
    pub balance: BigDecimal,
    pub invoice_id: String,
    pub payer: String,
    pub payee: String,
    pub credit_amount: BigDecimal,
    pub hold_for_pickup_link: String,
    #[serde(default)]
    pub acs_uri: Option<String>,
    #[serde(default)]
    pub acs_params: Option<Value>,
    pub digital_goods: Value,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProcessPaymentResponse {
    Success(ProcessPaymentSuccessData),
    Refused { error: String },
    InProgress { next_retry: u64 },
    ExtAuthRequired,
    AccountBlocked { account_unblock_uri: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ProcessPaymentError {
    Refused { error: String },
    InProgress { next_retry: u64 },
    ExtAuthRequired,
    AccountBlocked { account_unblock_uri: String },
}

impl ProcessPaymentResponse {
    #[allow(clippy::missing_errors_doc)]
    pub fn into_result(self) -> Result<ProcessPaymentSuccessData, ProcessPaymentError> {
        Err(match self {
            Self::Success(data) => return Ok(data),
            Self::Refused { error } => ProcessPaymentError::Refused { error },
            Self::InProgress { next_retry } => ProcessPaymentError::InProgress { next_retry },
            Self::ExtAuthRequired => ProcessPaymentError::ExtAuthRequired,
            Self::AccountBlocked {
                account_unblock_uri,
            } => ProcessPaymentError::AccountBlocked {
                account_unblock_uri,
            },
        })
    }
}
