# -*- coding: utf-8 -*-

{
    "name": "Saudi Arabia e-invoice Phase 2 (Integration Phase)",
    "version": "11.0.1.4.5",
    "category": "Accounting & Finance",
    "license": "OPL-1",
    "summary": "Generates electronic invoicing for Saudi Arabia distribution according to ZATCA requirements",
    "price": 1050.0,
    "currency": "USD",
    "author": "HMPRO",
    "website": "",
    "depends": ["account_invoicing"],
    "data": [
        "views/account_invoice.xml",
        "views/partner_view.xml",
        "views/company_view.xml",
        "views/report_invoice.xml",
        "views/assets.xml",
        "views/res_config_settings_views.xml",
        "data/invoice_template.xml",
        "security/ir.model.access.csv",
    ],
    "installable": True,
    "images": ["static/description/banner.png"],
    "live_test_url": "https://youtu.be/bvcZhKrMFXY",
}
