# -*- coding: utf-8 -*-

from odoo import fields, models, api


class ResConfigSettings(models.TransientModel):
    _inherit = "res.config.settings"

    zatca_server = fields.Char(related='company_id.zatca_server', readonly=False)
    is_prd = fields.Selection(related='company_id.is_prd', readonly=False)
    zatca_auto_send = fields.Boolean(
        string="auto send",
        help="Automatic sending of electronic invoices after Confirmation",
        config_parameter="l10n_sa_e-invoice.zatca_auto_send",
    )

    # @api.model
    # def get_values(self):
    #     res = super(ResConfigSettings, self).get_values()
    #     company = self.env.user.company_id
    #     res.update(
    #         zatca_server=company.zatca_server,
    #     )
    #     return res

    # def set_values(self):
    #     super(ResConfigSettings, self).set_values()
    #     self.env["res.company"].sudo().search([]).write({"zatca_server": self.zatca_server})
