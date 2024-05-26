# -*- coding: utf-8 -*-

from odoo import models, fields, _, api
from odoo.exceptions import UserError, ValidationError
from requests.exceptions import HTTPError, RequestException
from odoo.modules.module import get_module_resource
import subprocess, os, tempfile
import base64, re, uuid
import requests
import json
import logging

logger = logging.getLogger(__name__)

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend
    from cryptography import x509
    from cryptography.x509 import ObjectIdentifier, load_der_x509_certificate
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.serialization import Encoding, load_pem_private_key
except:
    logger.warning("Cannot import OpenSSL library")

ZATCA_API_URLS = {
    "sandbox": "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal",
    "no": "https://gw-fatoora.zatca.gov.sa/e-invoicing/simulation",
    "yes": "https://gw-fatoora.zatca.gov.sa/e-invoicing/core",
}

CERT_TEMPLATE_NAME = {
    'sandbox': b'\x13\x15PREZATCA-Code-Signing',
    'no': b'\x13\x15PREZATCA-Code-Signing',
    'yes': b'\x0c\x12ZATCA-Code-Signing',
}

class ResCompany(models.Model):
    _inherit = "res.company"

    building_number = fields.Char("Building Number", related="partner_id.building_number", readonly=False)
    plot_identification = fields.Char("Plot Identification", related="partner_id.plot_identification", readonly=False)
    city_subdivision = fields.Char("City Subdivision Name", related="partner_id.city_subdivision", readonly=False)

    business_category = fields.Char(string="Business Category", default="")
    otp = fields.Char(string="OTP", default="")
    serial_number = fields.Char("Serial Number", readonly=True, copy=False)
    invoice_type_t = fields.Boolean(string="Tax invoice (standard)", default=1)
    invoice_type_s = fields.Boolean(string="Simplified tax invoice", default=1)
    request_id = fields.Char(string="requestID", default="")
    digital_certificate = fields.Text(string="Username", default="")
    password_secret = fields.Char(string="Password", default="")
    compliance_request_id = fields.Char(string="Compliance requestID", default="")
    compliance_digital_certificate = fields.Text(string="Compliance Username", default="")
    compliance_password_secret = fields.Char(string="Compliance Password", default="")
    is_prd = fields.Selection([("yes", "PRODUCTION"), ("no", "PREPROD"), ("sandbox", "SANDBOX")], default="sandbox", string="Environment")
    zatca_server = fields.Char(string="Server", default="https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal")
    xml_file = fields.Binary("invoice xml", attachment=True, copy=False)
    file_name = fields.Char(string="Name", size=64)
    compliance_checks = fields.One2many("compliance.checks", "company_id")

    pem_private_key = fields.Binary(attachment=False, groups="base.group_system", readonly=True, copy=False)
    encoded_csr = fields.Binary(attachment=True, copy=False, groups="base.group_system")
     
    def write(self, vals):
        for company in self:
            if 'is_prd' in vals:
                if company.digital_certificate != '' and company.is_prd == 'yes' and vals['is_prd'] != 'yes':
                    raise UserError("You cannot change the ZATCA Submission Mode once it has been set to Production")
                vals['zatca_server'] = ZATCA_API_URLS[vals['is_prd']]
                vals['digital_certificate'] = ''
                vals['password_secret'] = ''
                vals['compliance_digital_certificate'] = ''
                vals['compliance_password_secret'] = ''
                vals['request_id'] = ''
                vals['compliance_request_id'] = ''
        return super().write(vals)
    
    @api.model
    def create(self, vals):
        if 'is_prd' in vals:
            vals['zatca_server'] = ZATCA_API_URLS[vals['is_prd']]
        res = super().create(vals)
        return res

    def _default_serial_number(self):
        return "1-HMPRO|2-ETASA|3-" + str(uuid.uuid4())

    def _generate_private_key(self):
        private_key = ec.generate_private_key(ec.SECP256K1, default_backend())
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())

    def _check_csr_fields(self):
        msg = ""
        if not self.city:
            msg += "-Company address must contain (City)." + "\n"
        if not self.country_id:
            msg += "-Company address must contain (Country)." + "\n"
        if not self.state_id:
            msg += "-Company address must contain (State)." + "\n"
        if not self.vat:
            msg += (
                "-Company must contain the VAT registration number."
                + "\n"
            )
        if not self.otp:
            msg += (
                "-You need to provide an OTP to be able to request a CCSID."
                + "\n"
            )
        if msg:
            raise ValidationError(msg)

    def _generate_csr(self):
        self.ensure_one()
        self._check_csr_fields()

        def _encode(s):
            return s.encode().decode('CP1252')

        company_id = self
        builder = x509.CertificateSigningRequestBuilder()
        subject_names = (
            # Country Name
            (NameOID.COUNTRY_NAME, company_id.country_id.code),
            # Organization Unit Name
            (NameOID.ORGANIZATIONAL_UNIT_NAME, (company_id.vat or '')[:10]),
            # Organization Name
            (NameOID.ORGANIZATION_NAME, _encode(company_id.name)),
            # Subject Common Name
            (NameOID.COMMON_NAME, _encode(company_id.name)),
            # Organization Identifier
            (ObjectIdentifier('2.5.4.97'), company_id.vat),
            # State/Province Name
            (NameOID.STATE_OR_PROVINCE_NAME, _encode(company_id.state_id.name)),
            # Locality Name
            (NameOID.LOCALITY_NAME, _encode(company_id.city)),
        )
        # The CertificateSigningRequestBuilder instances are immutable, which is why everytime we modify one,
        # we have to assign it back to itself to keep track of the changes
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(n[0], u'%s' % n[1]) for n in subject_names
        ]))
        title = str(int(company_id.invoice_type_t)) + str(int(company_id.invoice_type_s)) + "00"
        if not company_id.serial_number:
            company_id.serial_number = "1-ODOOHM|2-ETASA|3-" + str(uuid.uuid4())
        x509_alt_names_extension = x509.SubjectAlternativeName([
            x509.DirectoryName(x509.Name([
                # EGS Serial Number. Manufacturer or Solution Provider Name, Model or Version and Serial Number.
                # To be written in the following format: "1-... |2-... |3-..."
                x509.NameAttribute(ObjectIdentifier('2.5.4.4'), _encode(company_id.serial_number)),
                # Organisation Identifier (UID)
                x509.NameAttribute(NameOID.USER_ID, company_id.vat),
                # Invoice Type. 4-digit numerical input using 0 & 1
                x509.NameAttribute(NameOID.TITLE, title),
                # Location
                x509.NameAttribute(ObjectIdentifier('2.5.4.26'), _encode(company_id.street)),
                # Industry
                x509.NameAttribute(ObjectIdentifier('2.5.4.15'),
                                   _encode(company_id.business_category or 'Other')),
            ]))
        ])

        x509_extensions = (
            # Add Certificate template name extension
            (x509.UnrecognizedExtension(ObjectIdentifier('1.3.6.1.4.1.311.20.2'),
                                        CERT_TEMPLATE_NAME[company_id.is_prd]), False),
            # Add alternative names extension
            (x509_alt_names_extension, False),
        )

        for ext in x509_extensions:
            builder = builder.add_extension(ext[0], critical=ext[1])
        private_pem = self._generate_private_key()
        private_key = load_pem_private_key(private_pem, password=None, backend=default_backend())
        request = builder.sign(private_key, hashes.SHA256(), default_backend())

        self.pem_private_key = base64.b64encode(private_pem)
        self.encoded_csr = base64.b64encode(request.public_bytes(Encoding.PEM)).decode()

    # ====== API Helper Methods =======

    def _get_authorization_header(self, digital_certificate, password_secre):
        auth_str = "%s:%s" % (digital_certificate, password_secre)
        return 'Basic ' + base64.b64encode(auth_str.encode()).decode()

    def _call_api(self, request_data, request_url, method):
        try:
            response = requests.request(method, request_url, data=request_data.get('body'),
                                                headers=request_data.get('header'))
            response.raise_for_status()
        except (ValueError, HTTPError) as ex:
            raise ValidationError("Server returned an unexpected error: %s" % (response.text or str(ex)))
        except RequestException as ex:
            raise ValidationError("Error:  %s" % (str(ex)))
        try:
            response_data = response.json()
        except json.decoder.JSONDecodeError:
            raise ValidationError("JSON response from ZATCA could not be decoded")
        if not response.ok and (response_data.get('errors') or response_data.get('warnings')):
            if isinstance(response_data, dict) and response_data.get('errors'):
                raise ValidationError("Invoice submission to ZATCA returned errors: %s" % (str(response_data['errors'])))
            raise ValidationError("Error:  %s" % (response.reason))
        return response_data

    def getComplianceCSID(self):
        self._generate_csr()
        
        if not self.zatca_server:
            raise ValidationError("Please add ZATCA Server first.")
        url = self.zatca_server + "/compliance"       
        request_data = {
            'body': json.dumps({"csr": self.encoded_csr}),
            'header': {
                "accept": "application/json",
                "OTP": self.otp or "",
                "Accept-Version": "V2",
                "Content-Type": "application/json",
                }
        }
        response_data = self._call_api(request_data, url, 'POST')
        self.compliance_request_id = response_data["requestID"]
        self.compliance_digital_certificate = response_data["binarySecurityToken"]
        self.compliance_password_secret = response_data["secret"]

    def getProductionCSID(self):
        if not self.zatca_server:
            raise ValidationError("Please add ZATCA Server first.")
        url = self.zatca_server + "/production/csids"
        user = self.compliance_digital_certificate
        pwd = self.compliance_password_secret
        request_data = {
            'body': json.dumps({"compliance_request_id": self.compliance_request_id}),
            'header': {
                "accept": "application/json",
                "Accept-Version": "V2",
                "Content-Type": "application/json",
                "Authorization": self._get_authorization_header(user, pwd)
                }
        }
        response_data = self._call_api(request_data, url, 'POST')
        self.request_id = response_data["requestID"]
        self.digital_certificate = response_data["binarySecurityToken"]
        self.password_secret = response_data["secret"]

    def action_zatca_onboarding_company_step(self):
        self.getComplianceCSID()
        self.onboardingComplianceChecks()
        self.getProductionCSID()

    def renewProductionCSID(self):
        if not self.zatca_server:
            raise ValidationError("Please add ZATCA Server first.")
        url = self.zatca_server + "/production/csids"
        user = self.digital_certificate
        pwd = self.password_secret
        request_data = {
            'body': json.dumps({"csr": self.encoded_csr}),
            'header': {
                "accept": "application/json",
                "OTP": self.otp or "",
                "accept-language": "en",
                "Accept-Version": "V2",
                "Content-Type": "application/json",
                "Authorization": self._get_authorization_header(user, pwd)
                }
        }
        response_data = self._call_api(request_data, url, 'PATCH')
        self.request_id = response_data["requestID"]
        self.digital_certificate = response_data["binarySecurityToken"]
        self.password_secret = response_data["secret"]

    def action_zatca_renewal_company_step(self):
        # self.getComplianceCSID()
        # self.onboardingComplianceChecks()
        self.renewProductionCSID()

    def callApiComplianceChecks(self, xml_string):
        xml_string, digest, QR, inv_uuid = self.env["account.invoice"].signe_xml(
            xml_string, self, self.compliance_digital_certificate
        )
        if not self.zatca_server:
            raise ValidationError("Please add ZATCA Server first.")
        url = self.zatca_server + "/compliance/invoices"
        user = self.compliance_digital_certificate
        pwd = self.compliance_password_secret
        request_data = {
            'body': json.dumps(
                {"invoiceHash": digest, "uuid": inv_uuid, "invoice": base64.b64encode(xml_string).decode("utf-8")}
            ),
            'header': {
                "accept": "application/json",
                "Accept-Language": "en",
                "Accept-Version": "V2",
                "Content-Type": "application/json",
                "Authorization": self._get_authorization_header(user, pwd)
                }
        }
        response_data = self._call_api(request_data, url, 'POST')
        return xml_string, response_data

    def complianceChecks(self):
        if not self.xml_file:
            self.env.user.notify_default(message="Empty XML Invoice!")
        xml_string = base64.b64decode(self.xml_file)
        xml_string, response = self.callApiComplianceChecks(xml_string)
        if response.status_code == 200:
            self.env.user.notify_success(message="Successful validation")
        elif response.status_code == 400:
            self.env.user.notify_warning(message="Submitted invoice is invalid")
        elif response.status_code == 401:
            self.env.user.notify_danger(message="Username and/or password are invalid")
        else:
            self.env.user.notify_danger(message="Service faces internal errors")

    def onboardingComplianceChecks(self):
        templates = {}
        if self.invoice_type_t:
            templates.update(
                {
                    "01_388": "standard_tax_invoice",
                    "01_381": "standard_credit_note",
                    "01_383": "standard_debit_note",
                }
            )
        if self.invoice_type_s:
            templates.update(
                {
                    "02_388": "simplified_invoice",
                    "02_381": "simplified_credit_note",
                    "02_383": "simplified_debit_note",
                }
            )
        template_values = {"record": self}
        self.compliance_checks = [(5, 0, 0)]
        for key, temp in templates.items():
            xml_string = self.env["ir.qweb"].render("l10n_sa_e-invoice.%s" % temp, template_values)
            xml_string, response = self.callApiComplianceChecks(xml_string)
            res = response
            if response:
                warning_messages = "\n".join([item["message"] for item in res["validationResults"]["warningMessages"]])
                error_messages = "\n".join([item["message"] for item in res["validationResults"]["errorMessages"]])
                self.compliance_checks = [
                    (
                        0,
                        0,
                        {
                            "xml_file": base64.b64encode(xml_string),
                            "file_name": "%s.xml" % temp,
                            "type": key,
                            "state": res["clearanceStatus"] or res["reportingStatus"],
                            "warning_messages": warning_messages,
                            "error_messages": error_messages,
                            "response_message_zatca": res,
                        },
                    )
                ]
        if not all(doc.state in ("REPORTED", "CLEARED") for doc in self.compliance_checks):
            return ValidationError("One or more compliance checks have failed or are not completed.")


class ComplianceChecks(models.Model):
    _name = "compliance.checks"
    _description = "ZATCA Compliance Checks"

    xml_file = fields.Binary("invoice xml", attachment=True, copy=False)
    file_name = fields.Char(string="Name", size=64)
    type = fields.Selection(
        [
            ("01_388", "Standard Tax Invoice (B2B)"),
            ("01_381", "Standard Credit Note (B2B)"),
            ("01_383", "Standard Debit Note (B2B)"),
            ("02_388", "Simplified Tax Invoice (B2C)"),
            ("02_381", "Simplified Credit Note (B2C)"),
            ("02_383", "Simplified Debit Note (B2C)"),
        ],
        string="Type",
    )
    state = fields.Char(string="Status", default="")
    warning_messages = fields.Text(string="Warning messages", readonly=True, copy=False)
    error_messages = fields.Text(string="Error messages", readonly=True, copy=False)
    response_message_zatca = fields.Text(string="Response ZATCA", readonly=True, copy=False)
    company_id = fields.Many2one("res.company", string="Company")
