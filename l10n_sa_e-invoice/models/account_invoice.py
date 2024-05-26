# -*- coding: utf-8 -*-

from odoo import fields, api, models, _
import base64
import qrcode
import io
from lxml import etree
import uuid
import hashlib
import requests
import json

from odoo.tools import float_is_zero, float_round
from odoo.exceptions import UserError, ValidationError
from odoo.modules.module import get_module_resource
from datetime import datetime, timedelta
from pytz import timezone
import logging

logger = logging.getLogger(__name__)

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.x509 import load_pem_x509_certificate
    import OpenSSL
    from OpenSSL import crypto

    type_ = crypto.FILETYPE_PEM
except:
    logger.warning("Cannot import OpenSSL library")

BC = b"-----BEGIN CERTIFICATE-----\n"
EC = b"\n-----END CERTIFICATE-----\n"

# This SANDBOX_AUTH is only used for testing purposes, and is shared to all users of the sandbox environment
SANDBOX_AUTH = {
    'binarySecurityToken': "TUlJRDFEQ0NBM21nQXdJQkFnSVRid0FBZTNVQVlWVTM0SS8rNVFBQkFBQjdkVEFLQmdncWhrak9QUVFEQWpCak1SVXdFd1lLQ1pJbWlaUHlMR1FCR1JZRmJHOWpZV3d4RXpBUkJnb0praWFKay9Jc1pBRVpGZ05uYjNZeEZ6QVZCZ29Ka2lhSmsvSXNaQUVaRmdkbGVIUm5ZWHAwTVJ3d0dnWURWUVFERXhOVVUxcEZTVTVXVDBsRFJTMVRkV0pEUVMweE1CNFhEVEl5TURZeE1qRTNOREExTWxvWERUSTBNRFl4TVRFM05EQTFNbG93U1RFTE1Ba0dBMVVFQmhNQ1UwRXhEakFNQmdOVkJBb1RCV0ZuYVd4bE1SWXdGQVlEVlFRTEV3MW9ZWGxoSUhsaFoyaHRiM1Z5TVJJd0VBWURWUVFERXdreE1qY3VNQzR3TGpFd1ZqQVFCZ2NxaGtqT1BRSUJCZ1VyZ1FRQUNnTkNBQVRUQUs5bHJUVmtvOXJrcTZaWWNjOUhEUlpQNGI5UzR6QTRLbTdZWEorc25UVmhMa3pVMEhzbVNYOVVuOGpEaFJUT0hES2FmdDhDL3V1VVk5MzR2dU1ObzRJQ0p6Q0NBaU13Z1lnR0ExVWRFUVNCZ0RCK3BId3dlakViTUJrR0ExVUVCQXdTTVMxb1lYbGhmREl0TWpNMGZETXRNVEV5TVI4d0hRWUtDWkltaVpQeUxHUUJBUXdQTXpBd01EYzFOVGc0TnpBd01EQXpNUTB3Q3dZRFZRUU1EQVF4TVRBd01SRXdEd1lEVlFRYURBaGFZWFJqWVNBeE1qRVlNQllHQTFVRUR3d1BSbTl2WkNCQ2RYTnphVzVsYzNNek1CMEdBMVVkRGdRV0JCU2dtSVdENmJQZmJiS2ttVHdPSlJYdkliSDlIakFmQmdOVkhTTUVHREFXZ0JSMllJejdCcUNzWjFjMW5jK2FyS2NybVRXMUx6Qk9CZ05WSFI4RVJ6QkZNRU9nUWFBL2hqMW9kSFJ3T2k4dmRITjBZM0pzTG5waGRHTmhMbWR2ZGk1ellTOURaWEowUlc1eWIyeHNMMVJUV2tWSlRsWlBTVU5GTFZOMVlrTkJMVEV1WTNKc01JR3RCZ2dyQmdFRkJRY0JBUVNCb0RDQm5UQnVCZ2dyQmdFRkJRY3dBWVppYUhSMGNEb3ZMM1J6ZEdOeWJDNTZZWFJqWVM1bmIzWXVjMkV2UTJWeWRFVnVjbTlzYkM5VVUxcEZhVzUyYjJsalpWTkRRVEV1WlhoMFoyRjZkQzVuYjNZdWJHOWpZV3hmVkZOYVJVbE9WazlKUTBVdFUzVmlRMEV0TVNneEtTNWpjblF3S3dZSUt3WUJCUVVITUFHR0gyaDBkSEE2THk5MGMzUmpjbXd1ZW1GMFkyRXVaMjkyTG5OaEwyOWpjM0F3RGdZRFZSMFBBUUgvQkFRREFnZUFNQjBHQTFVZEpRUVdNQlFHQ0NzR0FRVUZCd01DQmdnckJnRUZCUWNEQXpBbkJna3JCZ0VFQVlJM0ZRb0VHakFZTUFvR0NDc0dBUVVGQndNQ01Bb0dDQ3NHQVFVRkJ3TURNQW9HQ0NxR1NNNDlCQU1DQTBrQU1FWUNJUUNWd0RNY3E2UE8rTWNtc0JYVXovdjFHZGhHcDdycVNhMkF4VEtTdjgzOElBSWhBT0JOREJ0OSszRFNsaWpvVmZ4enJkRGg1MjhXQzM3c21FZG9HV1ZyU3BHMQ==",
    'secret': "Xlj15LyMCgSC66ObnEO/qVPfhSbs3kDTjWnGheYhfSs="
}


class AccountInvoice(models.Model):
    _inherit = "account.invoice"

    cryptographic_uuid = fields.Char(
        "UUID",
        readonly=True,
        copy=False,
        help="This will help to identify cryptographic hash uuid",
    )
    sha256 = fields.Char(
        "SHA256",
        readonly=True,
        copy=False,
        help="This will help to identify hash code",
    )
    edi_counter = fields.Integer("ICV", copy=False, readonly=True)
    # payment_mode_id = fields.Many2one(
    #     comodel_name="account.payment.mode",
    #     string="Payment Mode",
    #     ondelete="restrict",
    #     readonly=True,
    #     states={"draft": [("readonly", False)]},
    # )
    xml_content = fields.Text(string="Contents XML", readonly=True, copy=False)
    xml_file = fields.Many2one("ir.attachment", readonly=True, copy=False)
    l10n_sa_qr_code_str = fields.Char(
        string="Zatca QR Code",
        readonly=True,
        copy=False,
        help="This will help to identify QR code",
    )
    l10n_sa_qr_code = fields.Binary(string="QRCode", compute="_compute_qr_code", readonly=True)
    l10n_sa_delivery_date = fields.Date(
        string="Delivery Date",
        default=fields.Date.context_today,
        copy=False,
        readonly=True,
        states={"draft": [("readonly", False)]},
        help="In case of multiple deliveries, you should take the date of the latest one. ",
    )
    l10n_sa_show_delivery_date = fields.Boolean(compute="_compute_show_delivery_date")
    l10n_sa_confirmation_datetime = fields.Datetime(string="Confirmation Date", readonly=True, copy=False)
    response_message_zatca = fields.Text(string="Response ZATCA", readonly=True, copy=False)
    cleared_invoice = fields.Text(string="Cleared XML", readonly=True, copy=False)
    l10n_sa_send_state = fields.Selection(
        [("reported", "Reported"), ("cleared", "Cleared"), ("invalid", "Invalid"), ("rejected", "Rejected")],
        string="E-Invoice Status",
        readonly=True,
        copy=False,
        tracking=True,
    )
    warning_messages = fields.Text(string="Warning messages", readonly=True, copy=False)
    error_messages = fields.Text(string="Error messages", readonly=True, copy=False)
    si_remaining_hours = fields.Integer(
        compute="_get_remaining_hours",
        string="Remaining Hours",
        help="Shows the remaining hours to report Simplified Invoice",
    )
    last_time_sent = fields.Datetime(
        string="Latest sent", readonly=True, copy=False, help="Last time the e-invoices was sent."
    )
    position3 = fields.Boolean(string="3rd Party invoice", default=False, copy=False)
    position4 = fields.Boolean(string="Nominal invoice", default=False, copy=False)
    position5 = fields.Boolean(string="Exports invoice", default=False, copy=False)
    position6 = fields.Boolean(string="Summary invoice", default=False, copy=False)
    position7 = fields.Boolean(string="Self billed invoice", default=False, copy=False)

    @api.constrains("position5", "position7", "partner_id")
    def _check_InvoiceTypeCode(self):
        for record in self:
            if record.position5 and record.position7:
                raise UserError("Self-billing is not allowed for export invoices")
            if record.partner_id.company_type != "company" and (record.position5 or record.position7):
                error_message = (
                    "For simplified tax invoices and associated credit notes and debit notes, only the following are accepted:\n"
                    "third party invoice\n"
                    "nominal supply invoice\n"
                    "summary transactions invoice\n"
                )
                raise UserError(error_message)

    @api.depends("company_id.country_id.code", "type")
    def _compute_show_delivery_date(self):
        for invoice in self:
            invoice.l10n_sa_show_delivery_date = invoice.company_id.country_id.code == "SA" and invoice.type in (
                "out_invoice",
                "out_refund",
            )

    @api.one
    @api.depends("l10n_sa_confirmation_datetime")
    def _get_remaining_hours(self):
        for record in self:
            if (
                record.l10n_sa_confirmation_datetime
                and record.partner_id.company_type != "company"
                and record.l10n_sa_send_state != "reported"
            ):
                current_date = datetime.now()
                limit_date = fields.Datetime.from_string(record.l10n_sa_confirmation_datetime) + timedelta(hours=24)
                number_of_hours = (limit_date - current_date).total_seconds() / 3600.0
                if number_of_hours > 0:
                    record.si_remaining_hours = number_of_hours
                else:
                    record.si_remaining_hours = 0
            else:
                record.si_remaining_hours = 25

    @api.depends("l10n_sa_qr_code_str")
    def _compute_qr_code(self):
        for rec in self:
            rec.l10n_sa_qr_code = False
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=3,
                border=4,
            )

            qr.add_data(rec.l10n_sa_qr_code_str)
            qr.make(fit=True)
            img = qr.make_image()
            temp = io.BytesIO()
            img.save(temp, format="PNG")
            qr_code_image = base64.b64encode(temp.getvalue())
            rec.l10n_sa_qr_code = qr_code_image

    # def _default_cryptographic_uuid(self):
    #     return str(uuid.uuid4())

    def ensure_str(self, x, encoding="utf-8", none_ok=False):
        if none_ok is True and x is None:
            return x
        if not isinstance(x, str):
            x = x.decode(encoding)
        return x

    def _template_signature_data_xml(self):
        template_signature_data_xml = """<ext:UBLExtensions xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2">
        <ext:UBLExtension>
            <ext:ExtensionURI>urn:oasis:names:specification:ubl:dsig:enveloped:xades</ext:ExtensionURI>
            <ext:ExtensionContent>
                <sig:UBLDocumentSignatures xmlns:sig="urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2" xmlns:sac="urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2" xmlns:sbc="urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2">
                    <sac:SignatureInformation>
                        <cbc:ID xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">urn:oasis:names:specification:ubl:signature:1</cbc:ID>
                        <sbc:ReferencedSignatureID>urn:oasis:names:specification:ubl:signature:Invoice</sbc:ReferencedSignatureID>
                        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="signature">
                            <ds:SignedInfo>
                                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>
                                <ds:Reference Id="invoiceSignedData" URI="">
                                    <ds:Transforms>
                                        <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                                            <ds:XPath>not(//ancestor-or-self::ext:UBLExtensions)</ds:XPath>
                                        </ds:Transform>
                                        <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                                            <ds:XPath>not(//ancestor-or-self::cac:Signature)</ds:XPath>
                                        </ds:Transform>
                                        <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                                            <ds:XPath>not(//ancestor-or-self::cac:AdditionalDocumentReference[cbc:ID='QR'])</ds:XPath>
                                        </ds:Transform>
                                        <ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                                    </ds:Transforms>
                                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                                    <ds:DigestValue>%(InvoiceHash)s</ds:DigestValue>
                                </ds:Reference>
                                <ds:Reference Type="http://www.w3.org/2000/09/xmldsig#SignatureProperties" URI="#xadesSignedProperties">
                                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                                    <ds:DigestValue>%(SignedProperties)s</ds:DigestValue>
                                </ds:Reference>
                            </ds:SignedInfo>
                            <ds:SignatureValue>%(DigitalSignature)s</ds:SignatureValue>
                            <ds:KeyInfo>
                                <ds:X509Data>
                                    <ds:X509Certificate>%(certificate_base)s</ds:X509Certificate>
                                </ds:X509Data>
                            </ds:KeyInfo>
                            <ds:Object>
                                <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Target="signature">
                                    %(SignedProperties_base)s
                                </xades:QualifyingProperties>
                            </ds:Object>
                        </ds:Signature>
                    </sac:SignatureInformation>
                </sig:UBLDocumentSignatures>
            </ext:ExtensionContent>
        </ext:UBLExtension>
    </ext:UBLExtensions>"""
        return template_signature_data_xml

    def _template_signed_properties_data_xml(self):
        template_signed_properties_data_xml = """<xades:SignedProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="xadesSignedProperties">
                                      <xades:SignedSignatureProperties>
                                        <xades:SigningTime>%(data_xml_SigningTime)s</xades:SigningTime>
                                        <xades:SigningCertificate>
                                          <xades:Cert>
                                            <xades:CertDigest>
                                              <ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                                              <ds:DigestValue xmlns:ds="http://www.w3.org/2000/09/xmldsig#">%(CertDigestDigestValue)s</ds:DigestValue>
                                            </xades:CertDigest>
                                            <xades:IssuerSerial>
                                              <ds:X509IssuerName xmlns:ds="http://www.w3.org/2000/09/xmldsig#">%(IssuerName)s</ds:X509IssuerName>
                                              <ds:X509SerialNumber xmlns:ds="http://www.w3.org/2000/09/xmldsig#">%(SerialNumber)s</ds:X509SerialNumber>
                                            </xades:IssuerSerial>
                                          </xades:Cert>
                                        </xades:SigningCertificate>
                                      </xades:SignedSignatureProperties>
                                    </xades:SignedProperties>"""
        return template_signed_properties_data_xml

    def get_signature(self, message, cert, PrivateKey):
        parser = etree.XMLParser(recover=True)
        root = etree.fromstring(message.decode("utf-8").encode("utf-8"), parser)
        nsmapo, root_nsmap = self._get_nsmap_namespace("Invoice-2")
        del nsmapo[None]
        nss_ext = {"ext": nsmapo["ext"]}
        nss_cac = {"cac": nsmapo["cac"]}
        nss_cbc = {"cbc": nsmapo["cbc"]}
        for subtag in root.findall("ext:UBLExtensions", nss_ext):
            root.remove(subtag)
        for subtag in root.findall("cac:AdditionalDocumentReference", nss_cac):
            if subtag.find("cbc:ID", nss_cbc).text == "QR":
                root.remove(subtag)
        for subtag in root.findall("cac:Signature", nss_cac):
            root.remove(subtag)
        ## Step 1: Generate Invoice Hash
        string_xml = etree.tostring(root)
        c14n = etree.tostring(
            etree.fromstring(string_xml),
            method="c14n",
            exclusive=False,
            with_comments=False,
            inclusive_ns_prefixes=None,
        )
        digest_msg = hashlib.sha256(c14n).digest()
        digest = self.ensure_str(base64.b64encode(digest_msg))
        ## Step 2: Generate Digital Signature
        key = load_pem_private_key(PrivateKey, password=None, backend=default_backend())
        digital_signature = key.sign(digest_msg, ec.ECDSA(SHA256()))
        encoded_digital_signature = self.ensure_str(base64.b64encode(digital_signature))
        ## Step 3: Generate Certificate Hash
        cert_hash = hashlib.sha256(cert).hexdigest()
        encoded_cert_hash = self.ensure_str(base64.b64encode(cert_hash.encode()))
        ## Step 4: Populate the Signed Properties Output
        certificate = load_pem_x509_certificate(BC + cert + EC, default_backend())
        certificate_serial_number = certificate.serial_number
        certificate_issuer_info = certificate.issuer.rfc4514_string().replace(",", ", ")
        if not certificate_issuer_info.startswith("CN"):
            list = certificate_issuer_info.split(", ")
            list.reverse()
            certificate_issuer_info = ", ".join(list)
        template_signed_properties_data_xml = self._template_signed_properties_data_xml()
        template_signature_data_xml = self._template_signature_data_xml()
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        now_utc = datetime.now(timezone("UTC"))
        data_xml_SigningTime = now_utc.strftime(fmt)
        signed_properties_data_xml = template_signed_properties_data_xml % {
            "data_xml_SigningTime": data_xml_SigningTime,
            "CertDigestDigestValue": encoded_cert_hash,
            "IssuerName": certificate_issuer_info,
            "SerialNumber": str(certificate_serial_number),
        }
        ## Step 5: Generate Signed Properties Hash
        SignedProperties_hash = hashlib.sha256(signed_properties_data_xml.encode()).hexdigest()
        EncodedSignedProperties_hash = self.ensure_str(base64.b64encode(SignedProperties_hash.encode()))
        ## Step 6: Populate The UBL Extensions Output
        data_xml_signature = template_signature_data_xml % {
            "InvoiceHash": digest,
            "SignedProperties": EncodedSignedProperties_hash,
            "DigitalSignature": encoded_digital_signature,
            "certificate_base": cert.decode("utf-8"),
            "SignedProperties_base": signed_properties_data_xml,
        }
        root.insert(0, etree.fromstring(data_xml_signature))
        ## Generate QR Code
        try:
            tag1 = root.xpath(
                "//cac:AccountingSupplierParty/cac:Party/cac:PartyLegalEntity/cbc:RegistrationName", namespaces=nsmapo
            )[0].text
            tag2 = root.xpath(
                "//cac:AccountingSupplierParty/cac:Party/cac:PartyTaxScheme/cbc:CompanyID", namespaces=nsmapo
            )[0].text
            tag3 = root.find("cbc:IssueDate", nss_cbc).text + "T" + root.find("cbc:IssueTime", nss_cbc).text
            tag4 = root.xpath("//cac:LegalMonetaryTotal/cbc:TaxInclusiveAmount", namespaces=nsmapo)[0].text
            tag5 = root.xpath("//cac:TaxTotal/cbc:TaxAmount", namespaces=nsmapo)[0].text
            inv_uuid = root.find("cbc:UUID", nss_cbc).text
            invoiceType = root.xpath("//cbc:InvoiceTypeCode/@name", namespaces=nsmapo)[0]
            isSimplified = invoiceType.startswith("02")
        except:
            raise ValidationError("Invalid XML!")
        tag6 = digest
        tag7 = encoded_digital_signature
        public_key = certificate.public_key()
        tag8 = public_key.public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        tag9 = certificate.signature
        QR = self.generate_zatca_code(isSimplified, tag1, tag2, tag3, tag4, tag5, tag6, tag7, tag8, tag9)
        qr_code = etree.Element(root_nsmap["cac"] + "AdditionalDocumentReference")
        qr_reference_id = etree.SubElement(qr_code, root_nsmap["cbc"] + "ID")
        qr_reference_id.text = "QR"
        qr_attach_node = etree.SubElement(qr_code, root_nsmap["cac"] + "Attachment")
        qr_binary_node = etree.SubElement(
            qr_attach_node, root_nsmap["cbc"] + "EmbeddedDocumentBinaryObject", mimeCode="text/plain"
        )
        qr_binary_node.text = QR
        ## Add Signature tag
        signature = etree.Element(root_nsmap["cac"] + "Signature")
        signature_id = etree.SubElement(signature, root_nsmap["cbc"] + "ID")
        signature_id.text = "urn:oasis:names:specification:ubl:signature:Invoice"
        signature_method = etree.SubElement(signature, root_nsmap["cbc"] + "SignatureMethod")
        signature_method.text = "urn:oasis:names:specification:ubl:dsig:enveloped:xades"

        for subtag in root.findall("cac:AdditionalDocumentReference", nss_cac):
            if subtag.find("cbc:ID", nss_cbc).text == "PIH":
                qr_element = etree.tostring(qr_code, pretty_print=True, encoding="UTF-8", xml_declaration=True)
                signature_element = etree.tostring(signature, pretty_print=True, encoding="UTF-8", xml_declaration=True)
                root.insert(root.index(subtag) + 1, etree.fromstring(qr_element))
                root.insert(root.index(subtag) + 2, etree.fromstring(signature_element))

        data_xml = etree.tostring(root, pretty_print=True, encoding="UTF-8", xml_declaration=True)
        return data_xml, digest, QR, inv_uuid

    def signe_xml(self, msg, company_id, digital_certificate):
        if company_id.sudo().pem_private_key and digital_certificate:
            cert = base64.b64decode(digital_certificate)
            PrivateKey = base64.b64decode(company_id.sudo().pem_private_key)
        else:
            raise ValidationError("There is no ZATCA Configuration")
        return self.get_signature(msg, cert, PrivateKey)

    def CallAPI(self, url, ClearanceStatus):
        if not self.company_id.zatca_server:
            raise ValidationError("Please add ZATCA Server first.")
        url = self.company_id.zatca_server + url
        payload = json.dumps(
            {
                "invoiceHash": self.sha256,
                "uuid": self.cryptographic_uuid,
                "invoice": base64.b64encode(self.xml_content.encode("utf-8")).decode("utf-8"),
            }
        )
        headers = {
            "accept-language": "en",
            "Clearance-Status": ClearanceStatus,
            "Accept-Version": "V2",
            "Content-Type": "application/json",
        }
        user = self.company_id.digital_certificate
        pwd = self.company_id.password_secret
        try:
            response = requests.request("POST", url, headers=headers, data=payload, auth=(user, pwd))
        except:
            raise ValidationError("There is no communication with ZATCA")

        self.warning_messages = ""
        self.error_messages = ""
        if response.status_code in (200, 202):
            res = json.loads(response.text)
            if response.status_code == 202:
                warning_messages = "\n".join([item["message"] for item in res["validationResults"]["warningMessages"]])
                self.warning_messages = warning_messages
            self.response_message_zatca = res
            return res
            # raise ValidationError('Error 202 = The invoice is reported with warnings: %s'  % (warning_messages))
        elif response.status_code == 400:
            res = json.loads(response.text)
            self.l10n_sa_send_state = "invalid"
            error_messages = "\n".join([item["message"] for item in res["validationResults"]["errorMessages"]])
            self.error_messages = error_messages
            # raise ValidationError('Error 400 = The submitted request is invalid: %s'  % (error_messages))
        elif response.status_code == 401:
            self.l10n_sa_send_state = "rejected"
            self.error_messages = "Error 401 = Username and/or password are invalid"
            # raise ValidationError('Error 401 = Username and/or password are invalid')
        else:
            self.l10n_sa_send_state = "rejected"
            self.error_messages = "Error 500 = Something went wrong and caused an Internal Server Error."
            # raise ValidationError('Error 500 = Something went wrong and caused an Internal Server Error.')
        return False

    def CallClearanceAPI(self):
        url = "/invoices/clearance/single"
        res = self.CallAPI(url, "1")
        if res:
            self.cleared_invoice = res["clearedInvoice"]
            self.l10n_sa_send_state = "cleared"
            if self.cleared_invoice:
                xml_cleared_invoice = base64.b64decode(self.cleared_invoice)
                root = etree.fromstring(xml_cleared_invoice)
                nsmap = root.nsmap
                del nsmap[None]
                cleared_qr = root.xpath(
                    "//cac:AdditionalDocumentReference[cbc:ID='QR']/cac:Attachment/cbc:EmbeddedDocumentBinaryObject",
                    namespaces=nsmap,
                )[0].text
                self.l10n_sa_qr_code_str = cleared_qr

    def CallReportingAPI(self):
        url = "/invoices/reporting/single"
        ClearanceStatus = "1"
        res = self.CallAPI(url, ClearanceStatus)
        if res:
            self.l10n_sa_send_state = "reported"

    @api.multi
    def action_send_einvoices(self):
        invoices = self.filtered(
            lambda r: r.state in ("open", "paid")
            and r.company_id.country_id.code == "SA"
            and r.type in ("out_invoice", "out_refund")
            and r.l10n_sa_send_state not in ("reported", "cleared")
        )
        if not invoices:
            return
        for record in invoices:
            msg = ""
            if record.partner_id.company_type == "company" and record.partner_id.country_id.code == "SA":
                if not record.partner_id.building_number:
                    msg += "-Buyer address must contain (Building Number)." + "\n"
                if not record.partner_id.plot_identification:
                    msg += "-Buyer address must contain (Plot Identification)." + "\n"
                if not record.partner_id.city_subdivision:
                    msg += "-Buyer address must contain (City Subdivision Name)." + "\n"
            if not record.company_id.partner_id.building_number:
                msg += "-Seller address must contain (Building Number)." + "\n"
            if not record.company_id.partner_id.plot_identification:
                msg += "-Seller address must contain (Plot Identification)." + "\n"
            if not record.company_id.partner_id.city_subdivision:
                msg += "-Seller address must contain (City Subdivision Name)." + "\n"
            if not record.company_id.vat:
                msg += (
                    "-The invoice must contain the seller VAT registration number or seller group VAT registration number."
                    + "\n"
                )
            if msg:
                raise ValidationError(msg)
            if record.xml_file.id and record.l10n_sa_send_state == False:
                logger.info("already generated")
            else:
                record.attach_generated_xml()
            if record.partner_id.company_type == "company":
                record.CallClearanceAPI()
            else:
                record.CallReportingAPI()
            record.last_time_sent = fields.Datetime.now()

    @api.model
    def get_previous_invoice(self):
        invoice_ids = self.env["account.invoice"].search(
            [
                ("type", "in", ("out_invoice", "out_refund")),
                ("company_id", "=", self.company_id.id),
                ("l10n_sa_send_state", "!=", False),
            ],
            order="last_time_sent desc",
            limit=1,
        )
        if invoice_ids:
            previous_invoice = invoice_ids
        else:
            previous_invoice = False
        return previous_invoice

    @api.model
    def _encrypt_string(self, hash_string):
        if hash_string:
            hash_string = self.browse(hash_string)
            if hash_string.sha256:
                return hash_string.sha256
        sha_signature = hashlib.sha256(str(hash_string).encode()).hexdigest()
        encoded_sha_signature = base64.b64encode(sha_signature.encode())
        return encoded_sha_signature

    @api.model
    def _get_count_invoice(self):
        invoice_sent = self.env["account.invoice"].search(
            [
                ("type", "in", ("out_invoice", "out_refund")),
                ("company_id", "=", self.company_id.id),
                ("l10n_sa_send_state", "!=", False),
            ]
        )
        counter = max([edi_counter for edi_counter in invoice_sent.mapped("edi_counter") if edi_counter > 0], default=0)
        return counter

    @api.model
    def _get_lines_invoice(self):
        count = len(self.invoice_line_ids)
        return str(count)

    def get_qr_encoding(self, tag, field):
        company_name_byte_array = field.encode("UTF-8") if tag < 8 else field
        company_name_tag_encoding = tag.to_bytes(length=1, byteorder="big")
        company_name_length_encoding = len(company_name_byte_array).to_bytes(length=1, byteorder="big")
        return company_name_tag_encoding + company_name_length_encoding + company_name_byte_array

    def generate_zatca_code(self, isSimplified, tag1, tag2, tag3, tag4, tag5, tag6, tag7, tag8, tag9):
        qr_code_str = ""
        seller_name_enc = self.get_qr_encoding(1, tag1)
        company_vat_enc = self.get_qr_encoding(2, tag2 or "")
        timestamp_enc = self.get_qr_encoding(3, tag3)
        invoice_total_enc = self.get_qr_encoding(4, tag4)
        total_vat_enc = self.get_qr_encoding(5, tag5)
        sha256_enc = self.get_qr_encoding(6, tag6)
        tag7 = self.get_qr_encoding(7, tag7)
        tag8 = self.get_qr_encoding(8, tag8)
        tag9 = self.get_qr_encoding(9, tag9) if isSimplified else b""
        str_to_encode = (
            seller_name_enc
            + company_vat_enc
            + timestamp_enc
            + invoice_total_enc
            + total_vat_enc
            + sha256_enc
            + tag7
            + tag8
            + tag9
        )
        qr_code_str = base64.b64encode(str_to_encode).decode("UTF-8")
        return qr_code_str

    @api.model
    def _get_nsmap_namespace(self, doc_name):
        nsmap = {
            None: "urn:oasis:names:specification:ubl:schema:xsd:" + doc_name,
            "cac": "urn:oasis:names:specification:ubl:" "schema:xsd:CommonAggregateComponents-2",
            "cbc": "urn:oasis:names:specification:ubl:schema:xsd:" "CommonBasicComponents-2",
            "ext": "urn:oasis:names:specification:ubl:schema:xsd:" "CommonExtensionComponents-2",
        }
        ns = {
            "cac": "{urn:oasis:names:specification:ubl:schema:xsd:" "CommonAggregateComponents-2}",
            "cbc": "{urn:oasis:names:specification:ubl:schema:xsd:" "CommonBasicComponents-2}",
            "ext": "{urn:oasis:names:specification:ubl:schema:xsd:" "CommonExtensionComponents-2}",
        }
        return nsmap, ns

    @api.multi
    def _xml_add_header(self, parent_node, ns, ProfileID="reporting:1.0"):
        Profile_id = etree.SubElement(parent_node, ns["cbc"] + "ProfileID")
        Profile_id.text = ProfileID
        doc_id = etree.SubElement(parent_node, ns["cbc"] + "ID")
        doc_id.text = self.number
        doc_uuid = etree.SubElement(parent_node, ns["cbc"] + "UUID")
        # if not self.cryptographic_uuid:
        self.cryptographic_uuid = str(uuid.uuid4())
        doc_uuid.text = self.cryptographic_uuid
        issue_date = etree.SubElement(parent_node, ns["cbc"] + "IssueDate")
        issue_date.text = fields.Datetime.from_string(self.l10n_sa_confirmation_datetime).strftime("%Y-%m-%d")
        issue_time = etree.SubElement(parent_node, ns["cbc"] + "IssueTime")
        issue_time.text = fields.Datetime.from_string(self.l10n_sa_confirmation_datetime).strftime("%H:%M:%S")
        move_type = "01" if self.partner_id.company_type == "company" else "02"
        name_tag = (
            move_type
            + str(int(self.position3))
            + str(int(self.position4))
            + str(int(self.position5))
            + str(int(self.position6))
            + str(int(self.position7))
        )
        type_code = etree.SubElement(parent_node, ns["cbc"] + "InvoiceTypeCode", name=name_tag)
        if self.type == "out_invoice":
            if ("debit_invoice_id" in self) and self.debit_invoice_id:
                # Debit note
                type_code.text = "383"
            else:
                # Sales invoice
                type_code.text = "388"
        elif self.type == "out_refund":
            # Credit note
            type_code.text = "381"
        if self.comment:
            note = etree.SubElement(parent_node, ns["cbc"] + "Note")
            note.text = self.comment
        doc_currency = etree.SubElement(parent_node, ns["cbc"] + "DocumentCurrencyCode")
        doc_currency.text = self.currency_id.name
        tax_currency = etree.SubElement(parent_node, ns["cbc"] + "TaxCurrencyCode")
        tax_currency.text = self.company_currency_id.name
        count_lines = etree.SubElement(parent_node, ns["cbc"] + "LineCountNumeric")
        count_lines.text = self._get_lines_invoice()

    @api.multi
    def _xml_add_attachments(self, parent_node, ns):
        doc_counter = etree.SubElement(parent_node, ns["cac"] + "AdditionalDocumentReference")
        doc_counter_id = etree.SubElement(doc_counter, ns["cbc"] + "ID")
        doc_counter_id.text = "ICV"
        self.edi_counter = self._get_count_invoice() + 1
        doc_counter_uuid = etree.SubElement(doc_counter, ns["cbc"] + "UUID")
        doc_counter_uuid.text = str(self.edi_counter)
        # hash of the previous invoice
        previous_invoice = self.get_previous_invoice()
        sha256 = self._encrypt_string(previous_invoice and previous_invoice.id or 0)
        pi_reference = etree.SubElement(parent_node, ns["cac"] + "AdditionalDocumentReference")
        pi_reference_id = etree.SubElement(pi_reference, ns["cbc"] + "ID")
        pi_reference_id.text = "PIH"
        attach_node = etree.SubElement(pi_reference, ns["cac"] + "Attachment")
        binary_node = etree.SubElement(attach_node, ns["cbc"] + "EmbeddedDocumentBinaryObject", mimeCode="text/plain")
        binary_node.text = sha256

    @api.model
    def _xml_add_country(self, country, parent_node, ns):
        country_root = etree.SubElement(parent_node, ns["cac"] + "Country")
        country_code = etree.SubElement(country_root, ns["cbc"] + "IdentificationCode")
        country_code.text = country.code
        country_name = etree.SubElement(country_root, ns["cbc"] + "Name")
        country_name.text = country.name

    @api.model
    def _xml_add_address(self, partner, node_name, parent_node, ns):
        address = etree.SubElement(parent_node, ns["cac"] + node_name)
        if partner.street:
            streetname = etree.SubElement(address, ns["cbc"] + "StreetName")
            streetname.text = partner.street
        if partner.street2:
            addstreetname = etree.SubElement(address, ns["cbc"] + "AdditionalStreetName")
            addstreetname.text = partner.street2
        if partner.building_number:
            buildingnumber = etree.SubElement(address, ns["cbc"] + "BuildingNumber")
            buildingnumber.text = partner.building_number
        if partner.plot_identification:
            state_code = etree.SubElement(address, ns["cbc"] + "PlotIdentification")
            state_code.text = partner.plot_identification
        if partner.city_subdivision:
            addstreetname = etree.SubElement(address, ns["cbc"] + "CitySubdivisionName")
            addstreetname.text = partner.city_subdivision
        if partner.city:
            city = etree.SubElement(address, ns["cbc"] + "CityName")
            city.text = partner.city
        if partner.zip:
            zip = etree.SubElement(address, ns["cbc"] + "PostalZone")
            zip.text = partner.zip
        if partner.state_id:
            state = etree.SubElement(address, ns["cbc"] + "CountrySubentity")
            state.text = partner.state_id.name
        if partner.country_id:
            self._xml_add_country(partner.country_id, address, ns)
        else:
            logger.warning("Missing country on partner %s", partner.name)

    @api.model
    def _xml_add_party_identification(self, scheme_name, party_id_text, parent_node, ns):
        if party_id_text:
            party_identification = etree.SubElement(parent_node, ns["cac"] + "PartyIdentification")
            party_identification_id = etree.SubElement(party_identification, ns["cbc"] + "ID", schemeID=scheme_name)
            party_identification_id.text = party_id_text
        return

    @api.model
    def _xml_add_party_tax_scheme(self, commercial_partner, parent_node, ns):
        if commercial_partner.vat:
            party_tax_scheme = etree.SubElement(parent_node, ns["cac"] + "PartyTaxScheme")
            registration_name = etree.SubElement(party_tax_scheme, ns["cbc"] + "RegistrationName")
            registration_name.text = commercial_partner.name
            company_id = etree.SubElement(party_tax_scheme, ns["cbc"] + "CompanyID")
            company_id.text = commercial_partner.vat
            self._xml_add_tax_scheme(party_tax_scheme, ns)

    @api.model
    def _xml_add_party_legal_entity(self, commercial_partner, parent_node, ns):
        party_legal_entity = etree.SubElement(parent_node, ns["cac"] + "PartyLegalEntity")
        registration_name = etree.SubElement(party_legal_entity, ns["cbc"] + "RegistrationName")
        registration_name.text = commercial_partner.name

    @api.model
    def _xml_add_party(self, partner, company, node_name, parent_node, ns):
        commercial_partner = partner.commercial_partner_id
        party = etree.SubElement(parent_node, ns["cac"] + node_name)
        ## todo add other IDs
        if company:
            self._xml_add_party_identification("CRN", company.company_registry, party, ns)
        elif partner.vat:
            if len(partner.vat) == 15 and partner.vat[0] == partner.vat[-1] == "3":
                self._xml_add_party_identification("TIN", partner.vat, party, ns)
            else:
                logger.warning(
                    "The buyer VAT registration number must contain 15 digits. The first digit and the last digit is “3”. %s",
                    partner.name,
                )
        party_name = etree.SubElement(party, ns["cac"] + "PartyName")
        name = etree.SubElement(party_name, ns["cbc"] + "Name")
        name.text = commercial_partner.name
        self._xml_add_address(commercial_partner, "PostalAddress", party, ns)
        self._xml_add_party_tax_scheme(commercial_partner, party, ns)
        self._xml_add_party_legal_entity(commercial_partner, party, ns)

    @api.model
    def _xml_add_supplier_party(self, partner, company, parent_node, ns):
        if company:
            if partner:
                assert partner.commercial_partner_id == company.partner_id, "partner is wrong"
            else:
                partner = company.partner_id
        supplier_party_root = etree.SubElement(parent_node, ns["cac"] + "AccountingSupplierParty")
        self._xml_add_party(
            partner,
            company,
            "Party",
            supplier_party_root,
            ns,
        )

    @api.model
    def _xml_add_customer_party(self, partner, company, parent_node, ns):
        if company:
            if partner:
                assert partner.commercial_partner_id == company.partner_id, "partner is wrong"
            else:
                partner = company.partner_id
        customer_party_root = etree.SubElement(parent_node, ns["cac"] + "AccountingCustomerParty")
        self._xml_add_party(partner, company, "Party", customer_party_root, ns)

    @api.model
    def _xml_add_delivery(self, parent_node, ns):
        ## to check
        delivery = etree.SubElement(parent_node, ns["cac"] + "Delivery")
        delivery_Adate = etree.SubElement(delivery, ns["cbc"] + "ActualDeliveryDate")
        delivery_Adate.text = fields.Datetime.from_string(self.l10n_sa_delivery_date).strftime("%Y-%m-%d")
        delivery_Ldate = etree.SubElement(delivery, ns["cbc"] + "LatestDeliveryDate")
        delivery_Ldate.text = fields.Datetime.from_string(self.date_due).strftime("%Y-%m-%d")

    @api.model
    def _xml_add_payment_means(self, payment_mode, parent_node, ns):
        pay_means = etree.SubElement(parent_node, ns["cac"] + "PaymentMeans")
        pay_means_code = etree.SubElement(pay_means, ns["cbc"] + "PaymentMeansCode")
        if payment_mode and hasattr(payment_mode.payment_method_id, "unece_id"):
            if not payment_mode.payment_method_id.unece_id:
                raise UserError(
                    _("Missing 'UNECE Payment Mean' on payment type '%s' " "used by the payment mode '%s'.")
                    % (payment_mode.payment_method_id.name, payment_mode.name)
                )
            pay_means_code.text = payment_mode.payment_method_id.unece_code
        else:
            pay_means_code.text = "31"
            logger.warning(
                "Missing payment mode on invoice ID %d. "
                "Using 31 (wire transfer) as UNECE code as fallback "
                "for payment mean",
                self.id,
            )
        if self.type == "out_refund" or (
            self.type == "out_invoice" and ("debit_invoice_id" in self) and self.debit_invoice_id
        ):
            instruction_note = etree.SubElement(pay_means, ns["cbc"] + "InstructionNote")
            instruction_note.text = self.name

    @api.model
    def _xml_add_billing_reference(self, parent_node, ns):
        billing_reference = etree.SubElement(parent_node, ns["cac"] + "BillingReference")
        invoice_document_reference = etree.SubElement(billing_reference, ns["cac"] + "InvoiceDocumentReference")
        billing_reference_id = etree.SubElement(invoice_document_reference, ns["cbc"] + "ID")
        billing_reference_id.text = self.origin

    @api.model
    def _xml_add_tax_scheme(self, parent_node, ns):
        tax_scheme = etree.SubElement(parent_node, ns["cac"] + "TaxScheme")
        tax_scheme_id = etree.SubElement(tax_scheme, ns["cbc"] + "ID")
        tax_scheme_id.text = "VAT"

    @api.model
    def _xml_add_tax_category(self, tax, parent_node, ns, node_name="TaxCategory"):
        tax_category = etree.SubElement(parent_node, ns["cac"] + node_name)
        tax_category_id = etree.SubElement(tax_category, ns["cbc"] + "ID")
        tax_category_id.text = "S"
        tax_name = etree.SubElement(tax_category, ns["cbc"] + "Name")
        tax_name.text = tax.name
        if tax.amount_type == "percent":
            tax_percent = etree.SubElement(tax_category, ns["cbc"] + "Percent")
            tax_percent.text = str(tax.amount)
        self._xml_add_tax_scheme(tax_category, ns)

    @api.model
    def _xml_add_allowance_charge(self, discount, price_subtotal, parent_node, ns):
        cur_name = self.currency_id.name
        prec = self.currency_id.decimal_places
        prec = prec if prec <= 2 else 2
        allowance_charge = etree.SubElement(parent_node, ns["cac"] + "AllowanceCharge")
        charge_indicator = etree.SubElement(allowance_charge, ns["cbc"] + "ChargeIndicator")
        charge_indicator.text = "false"
        charge_indicator = etree.SubElement(allowance_charge, ns["cbc"] + "AllowanceChargeReasonCode")
        charge_indicator.text = "95"
        charge_indicator = etree.SubElement(allowance_charge, ns["cbc"] + "AllowanceChargeReason")
        charge_indicator.text = "Discount"
        factor_numeric = etree.SubElement(allowance_charge, ns["cbc"] + "MultiplierFactorNumeric")
        factor_numeric.text = "%0.*f" % (prec, discount)
        amount = price_subtotal * discount / (100.0 - discount)
        base_amount = price_subtotal + amount
        amount_node = etree.SubElement(allowance_charge, ns["cbc"] + "Amount", currencyID=cur_name)
        amount_node.text = "%0.*f" % (prec, amount)
        base_amount_node = etree.SubElement(allowance_charge, ns["cbc"] + "BaseAmount", currencyID=cur_name)
        base_amount_node.text = "%0.*f" % (prec, base_amount)

    @api.model
    def _xml_add_tax_subtotal(self, taxable_amount, tax_amount, tax, currency_code, parent_node, ns):
        prec = self.env["decimal.precision"].precision_get("Account")
        prec = prec if prec <= 2 else 2
        tax_subtotal = etree.SubElement(parent_node, ns["cac"] + "TaxSubtotal")
        if not float_is_zero(taxable_amount, precision_digits=prec):
            taxable_amount_node = etree.SubElement(tax_subtotal, ns["cbc"] + "TaxableAmount", currencyID=currency_code)
            taxable_amount_node.text = "%0.*f" % (prec, taxable_amount)
        tax_amount_node = etree.SubElement(tax_subtotal, ns["cbc"] + "TaxAmount", currencyID=currency_code)
        tax_amount_node.text = "%0.*f" % (prec, tax_amount)
        if tax.amount_type == "percent" and not float_is_zero(tax.amount, precision_digits=prec + 3):
            percent = etree.SubElement(tax_subtotal, ns["cbc"] + "Percent")
            percent.text = str(float_round(tax.amount, precision_digits=2))
        self._xml_add_tax_category(tax, tax_subtotal, ns)

    def _xml_add_tax_total(self, simplified, xml_root, ns):
        self.ensure_one()
        currency_id = self.currency_id if simplified == False else self.company_currency_id
        tax_total_node = etree.SubElement(xml_root, ns["cac"] + "TaxTotal")
        tax_amount_node = etree.SubElement(tax_total_node, ns["cbc"] + "TaxAmount", currencyID=currency_id.name)
        prec = currency_id.decimal_places
        prec = prec if prec <= 2 else 2
        amount_tax_company_signed = self.currency_id.compute(self.amount_tax, self.company_currency_id)
        tax_amount_node.text = "%0.*f" % (prec, amount_tax_company_signed)
        if simplified == False:
            tax_amount_node.text = "%0.*f" % (prec, self.amount_tax)
            for tline in self.tax_line_ids:
                self._xml_add_tax_subtotal(tline.base, tline.amount, tline.tax_id, currency_id.name, tax_total_node, ns)

    @api.multi
    def _xml_add_legal_monetary_total(self, parent_node, ns):
        monetary_total = etree.SubElement(parent_node, ns["cac"] + "LegalMonetaryTotal")
        cur_name = self.currency_id.name
        prec = self.currency_id.decimal_places
        prec = prec if prec <= 2 else 2
        line_total = etree.SubElement(monetary_total, ns["cbc"] + "LineExtensionAmount", currencyID=cur_name)
        line_total.text = "%0.*f" % (prec, self.amount_untaxed)
        tax_excl_total = etree.SubElement(monetary_total, ns["cbc"] + "TaxExclusiveAmount", currencyID=cur_name)
        tax_excl_total.text = "%0.*f" % (prec, self.amount_untaxed)
        tax_incl_total = etree.SubElement(monetary_total, ns["cbc"] + "TaxInclusiveAmount", currencyID=cur_name)
        tax_incl_total.text = "%0.*f" % (prec, self.amount_total)
        prepaid_amount = etree.SubElement(monetary_total, ns["cbc"] + "PrepaidAmount", currencyID=cur_name)
        prepaid_value = self.amount_total - self.residual
        prepaid_amount.text = "%0.*f" % (prec, prepaid_value)
        payable_amount = etree.SubElement(monetary_total, ns["cbc"] + "PayableAmount", currencyID=cur_name)
        payable_amount.text = "%0.*f" % (prec, self.residual)

    @api.model
    def _xml_add_item(self, line, parent_node, ns):
        """Beware that product may be False (in particular on invoices)"""
        assert line.name, "name is a required arg"
        item = etree.SubElement(parent_node, ns["cac"] + "Item")
        description = etree.SubElement(item, ns["cbc"] + "Description")
        description.text = line.name
        name_node = etree.SubElement(item, ns["cbc"] + "Name")
        name_node.text = line.name.split("\n")[0]
        if line.product_id:
            if line.product_id.barcode:
                std_identification = etree.SubElement(item, ns["cac"] + "StandardItemIdentification")
                std_identification_id = etree.SubElement(std_identification, ns["cbc"] + "ID")
                std_identification_id.text = line.product_id.barcode
        taxes = line.invoice_line_tax_ids
        if taxes:
            for tax in taxes:
                self._xml_add_tax_category(tax, item, ns, node_name="ClassifiedTaxCategory")

    @api.multi
    def _xml_add_invoice_line(self, parent_node, iline, line_number, ns):
        cur_name = self.currency_id.name
        line_root = etree.SubElement(parent_node, ns["cac"] + "InvoiceLine")
        dpo = self.env["decimal.precision"]
        qty_precision = dpo.precision_get("Product Unit of Measure")
        price_precision = dpo.precision_get("Product Price")
        price_precision = price_precision if price_precision <= 2 else 2
        account_precision = self.currency_id.decimal_places
        account_precision = account_precision if account_precision <= 2 else 2
        line_id = etree.SubElement(line_root, ns["cbc"] + "ID")
        line_id.text = str(line_number)
        uom_unece_code = False
        if iline.uom_id and hasattr(iline.uom_id, "unece_code") and iline.uom_id.unece_code:
            uom_unece_code = iline.uom_id.unece_code
        if uom_unece_code:
            quantity = etree.SubElement(line_root, ns["cbc"] + "InvoicedQuantity", unitCode=uom_unece_code)
        else:
            quantity = etree.SubElement(line_root, ns["cbc"] + "InvoicedQuantity")
        qty = iline.quantity
        quantity.text = "%0.*f" % (qty_precision, qty)
        line_amount = etree.SubElement(line_root, ns["cbc"] + "LineExtensionAmount", currencyID=cur_name)
        line_amount.text = "%0.*f" % (account_precision, iline.price_subtotal)
        if iline.discount:
            self._xml_add_allowance_charge(iline.discount, iline.price_subtotal, line_root, ns)
        self._xml_add_invoice_line_tax_total(iline, line_root, ns)
        self._xml_add_item(iline, line_root, ns)
        price_node = etree.SubElement(line_root, ns["cac"] + "Price")
        price_amount = etree.SubElement(price_node, ns["cbc"] + "PriceAmount", currencyID=cur_name)
        price_unit = 0.0
        if not float_is_zero(qty, precision_digits=qty_precision):
            price_unit = float_round(iline.price_unit, precision_digits=price_precision)
        price_amount.text = "%0.*f" % (price_precision, price_unit)

    def _xml_add_invoice_line_tax_total(self, iline, parent_node, ns):
        cur_name = self.currency_id.name
        prec = self.currency_id.decimal_places
        prec = prec if prec <= 2 else 2
        tax_total_node = etree.SubElement(parent_node, ns["cac"] + "TaxTotal")
        price = iline.price_unit * (1 - (iline.discount or 0.0) / 100.0)
        res_taxes = iline.invoice_line_tax_ids.compute_all(
            price, quantity=iline.quantity, product=iline.product_id, partner=self.partner_id
        )
        tax_total = float_round(res_taxes["total_included"] - res_taxes["total_excluded"], precision_digits=prec)
        tax_amount_node = etree.SubElement(tax_total_node, ns["cbc"] + "TaxAmount", currencyID=cur_name)
        tax_amount_node.text = "%0.*f" % (prec, tax_total)
        rounding_amount_node = etree.SubElement(tax_total_node, ns["cbc"] + "RoundingAmount", currencyID=cur_name)
        rounding_amount_node.text = "%0.*f" % (prec, res_taxes["total_included"])

    @api.multi
    def generate_invoice_xml_etree(self, ProfileID="reporting:1.0"):
        nsmap, ns = self._get_nsmap_namespace("Invoice-2")
        xml_root = etree.Element("Invoice", nsmap=nsmap)
        self._xml_add_header(xml_root, ns, ProfileID=ProfileID)
        if self.type == "out_refund" or (
            self.type == "out_invoice" and ("debit_invoice_id" in self) and self.debit_invoice_id
        ):
            self._xml_add_billing_reference(xml_root, ns)
        self._xml_add_attachments(xml_root, ns)
        self._xml_add_supplier_party(False, self.company_id, xml_root, ns)
        self._xml_add_customer_party(self.partner_id, False, xml_root, ns)
        self._xml_add_delivery(xml_root, ns)
        self._xml_add_payment_means(False, xml_root, ns)
        # self._xml_add_payment_means(self.payment_mode_id, xml_root, ns)
        ## todo add AllowanceCharge
        self._xml_add_tax_total(False, xml_root, ns)
        self._xml_add_tax_total(True, xml_root, ns)
        self._xml_add_legal_monetary_total(xml_root, ns)
        line_number = 0
        for iline in self.invoice_line_ids:
            line_number += 1
            self._xml_add_invoice_line(xml_root, iline, line_number, ns)
        return xml_root

    @api.multi
    def action_invoice_open(self):
        res = super(AccountInvoice, self).action_invoice_open()
        for record in self:
            if record.company_id.country_id.code == "SA" and record.type in ("out_invoice", "out_refund"):
                msg = ""
                # check data required by the ZATCA
                if any(len(l.invoice_line_tax_ids) != 1 for l in record.invoice_line_ids):
                    msg += "-Each Invoice line shall be categorized with an Invoiced item VAT category code." + "\n"
                if msg:
                    raise ValidationError(msg)
                record.write({"l10n_sa_confirmation_datetime": fields.Datetime.now()})
        zatca_auto_send = self.env["ir.config_parameter"].sudo().get_param("l10n_sa_e-invoice.zatca_auto_send")
        if zatca_auto_send:
            self.action_send_einvoices()
        return res

    @api.multi
    def generate_xml(self, ProfileID="reporting:1.0"):
        self.ensure_one()
        if not self.l10n_sa_confirmation_datetime:
            self.l10n_sa_confirmation_datetime = fields.Datetime.now()
        xml_root = self.generate_invoice_xml_etree(ProfileID=ProfileID)
        xml_string = etree.tostring(xml_root, pretty_print=True, encoding="UTF-8", xml_declaration=True)
        xml_string, digest, QR, inv_uuid = self.signe_xml(
            xml_string, self.company_id, self.company_id.digital_certificate
        )
        self.sha256 = digest
        self.l10n_sa_qr_code_str = QR
        return xml_string

    @api.multi
    def attach_generated_xml(self):
        self.ensure_one()
        xml_string = self.generate_xml(ProfileID="reporting:1.0")
        self.xml_content = xml_string
        if not self.xml_file:
            attach = self.env["ir.attachment"].create(
                {
                    "name": "E-Invoice-%s.xml" % self.number,
                    "res_id": self.id,
                    "res_model": str(self._name),
                    "datas": base64.b64encode(xml_string),
                    "datas_fname": "E-Invoice-%s.xml" % self.number,
                    "type": "binary",
                }
            )
            self.xml_file = attach.id
        else:
            self.xml_file.datas = base64.b64encode(xml_string)
            attach = self.xml_file
