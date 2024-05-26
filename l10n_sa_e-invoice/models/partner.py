# -*- coding: utf-8 -*-

from odoo import api, fields, models


class ResPartner(models.Model):
    """Add SA fields in address"""

    _inherit = "res.partner"

    building_number = fields.Char("Building Number")
    plot_identification = fields.Char("Plot Identification")
    city_subdivision = fields.Char("City Subdivision Name")

    @api.model
    def _address_fields(self):
        fields = super(ResPartner, self)._address_fields()
        fields.append('building_number')
        fields.append('plot_identification')
        fields.append('city_subdivision')
        return fields

    @api.multi
    def _display_address(self, without_company=False):
        """Remove empty lines which can happen when new field is empty."""
        res = super(ResPartner, self)._display_address(
            without_company=without_company)
        while '\n\n' in res:
            res = res.replace('\n\n', '\n')
        return res
