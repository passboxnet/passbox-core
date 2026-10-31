/**
 * Default fields per category. Mirrors `template` in
 * `crates/client/src/model.rs`; labels are English and apps show their own
 * for the well-known field IDs.
 */
import type { FieldFormat, FieldType, ItemCategory, ItemField } from "./items";

/** Well-known field IDs used for autofill, display and templates. */
export const FIELD = {
  username: "username",
  password: "password",
  url: "url",
  totp: "totp",
  cardholder: "cardholder",
  cardNumber: "card_number",
  cardExpiry: "card_expiry",
  cardCode: "card_code",
  firstName: "first_name",
  lastName: "last_name",
  fullName: "full_name",
  birthDate: "birth_date",
  email: "email",
  phone: "phone",
  address: "address",
  bankName: "bank_name",
  accountHolder: "account_holder",
  iban: "iban",
  bic: "bic",
  accountNumber: "account_number",
  pin: "pin",
  documentNumber: "document_number",
  nationality: "nationality",
  issueDate: "issue_date",
  expiryDate: "expiry_date",
  authority: "authority",
  licenseClasses: "license_classes",
  licenseKey: "license_key",
  licensedTo: "licensed_to",
  version: "version",
  purchaseDate: "purchase_date",
  wifiSsid: "wifi_ssid",
  wifiSecurity: "wifi_security",
  host: "host",
  port: "port",
  databaseType: "database_type",
  databaseName: "database_name",
  apiKey: "api_key",
  apiSecret: "api_secret",
  walletAddress: "wallet_address",
  recoveryPhrase: "recovery_phrase",
  network: "network",
  privateKey: "private_key",
  publicKey: "public_key",
  fingerprint: "fingerprint",
  passphrase: "passphrase",
} as const;

function f(id: string, label: string, type: FieldType = "text", format?: FieldFormat): ItemField {
  return format ? { id, label, type, value: "", format } : { id, label, type, value: "" };
}
const date = (id: string, label: string) => f(id, label, "text", "date");

/** Default fields for a new item of each category. */
export function templateFields(category: ItemCategory): ItemField[] {
  switch (category) {
    case "login":
      return [
        f(FIELD.username, "Username"),
        f(FIELD.password, "Password", "concealed"),
        f(FIELD.url, "Website", "url"),
        f(FIELD.totp, "One-time password", "totp"),
      ];
    case "card":
      return [
        f(FIELD.cardholder, "Cardholder"),
        f(FIELD.cardNumber, "Number", "concealed"),
        f(FIELD.cardExpiry, "Expiry date"),
        f(FIELD.cardCode, "Security code", "concealed"),
      ];
    case "identity":
      return [
        f(FIELD.firstName, "First name"),
        f(FIELD.lastName, "Last name"),
        date(FIELD.birthDate, "Date of birth"),
        f(FIELD.email, "Email", "email"),
        f(FIELD.phone, "Phone", "text", "phone"),
        f(FIELD.address, "Address", "text", "multiline"),
      ];
    case "bankAccount":
      return [
        f(FIELD.bankName, "Bank"),
        f(FIELD.accountHolder, "Account holder"),
        f(FIELD.iban, "IBAN"),
        f(FIELD.bic, "BIC"),
        f(FIELD.accountNumber, "Account number"),
        f(FIELD.pin, "PIN", "concealed"),
      ];
    case "idCard":
    case "passport":
      return [
        f(FIELD.fullName, "Full name"),
        f(FIELD.documentNumber, "Number"),
        f(FIELD.nationality, "Nationality"),
        date(FIELD.birthDate, "Date of birth"),
        date(FIELD.issueDate, "Issued on"),
        date(FIELD.expiryDate, "Expires on"),
        f(FIELD.authority, "Issuing authority"),
      ];
    case "driverLicense":
      return [
        f(FIELD.fullName, "Full name"),
        f(FIELD.documentNumber, "Number"),
        f(FIELD.licenseClasses, "Classes"),
        date(FIELD.birthDate, "Date of birth"),
        date(FIELD.issueDate, "Issued on"),
        date(FIELD.expiryDate, "Expires on"),
        f(FIELD.authority, "Issuing authority"),
      ];
    case "softwareLicense":
      return [
        f(FIELD.licenseKey, "License key", "concealed"),
        f(FIELD.licensedTo, "Licensed to"),
        f(FIELD.email, "Email", "email"),
        f(FIELD.version, "Version"),
        date(FIELD.purchaseDate, "Purchased on"),
        f(FIELD.url, "Website", "url"),
      ];
    case "wifi":
      return [
        f(FIELD.wifiSsid, "Network name"),
        f(FIELD.password, "Password", "concealed"),
        f(FIELD.wifiSecurity, "Security"),
      ];
    case "server":
      return [
        f(FIELD.url, "Address", "url"),
        f(FIELD.port, "Port"),
        f(FIELD.username, "Username"),
        f(FIELD.password, "Password", "concealed"),
      ];
    case "database":
      return [
        f(FIELD.databaseType, "Type"),
        f(FIELD.host, "Server"),
        f(FIELD.port, "Port"),
        f(FIELD.databaseName, "Database"),
        f(FIELD.username, "Username"),
        f(FIELD.password, "Password", "concealed"),
      ];
    case "apiCredential":
      return [
        f(FIELD.username, "Username"),
        f(FIELD.apiKey, "API key", "concealed"),
        f(FIELD.apiSecret, "Secret", "concealed"),
        f(FIELD.url, "Endpoint", "url"),
        date(FIELD.expiryDate, "Expires on"),
      ];
    case "cryptoWallet":
      return [
        f(FIELD.walletAddress, "Wallet address"),
        f(FIELD.recoveryPhrase, "Recovery phrase", "concealed", "multiline"),
        f(FIELD.password, "Password", "concealed"),
        f(FIELD.network, "Network"),
      ];
    case "sshKey":
      return [
        f(FIELD.privateKey, "Private key", "concealed", "multiline"),
        f(FIELD.publicKey, "Public key", "text", "multiline"),
        f(FIELD.fingerprint, "Fingerprint"),
        f(FIELD.passphrase, "Passphrase", "concealed"),
      ];
    default:
      return [];
  }
}
