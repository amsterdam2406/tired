from django.db import migrations, models


BANK_NAME_TO_CODE = {
    'access bank': '044',
    'gtbank': '058',
    'guaranty trust bank': '058',
    'first bank': '011',
    'first bank of nigeria': '011',
    'uba': '033',
    'united bank for africa': '033',
    'zenith bank': '057',
    'fidelity bank': '070',
    'union bank': '032',
    'union bank of nigeria': '032',
    'sterling bank': '232',
    'stanbic ibtc bank': '221',
    'polaris bank': '076',
    'wema bank': '035',
    'ecobank': '050',
    'ecobank nigeria': '050',
    'fcmb': '214',
    'first city monument bank': '214',
    'keystone bank': '082',
}


def populate_bank_codes(apps, schema_editor):
    Employee = apps.get_model('payroll', 'Employee')
    for employee in Employee.objects.filter(bank_code__isnull=True):
        bank_name = (employee.bank_name or '').strip().lower()
        bank_code = BANK_NAME_TO_CODE.get(bank_name)
        if bank_code:
            employee.bank_code = bank_code
            employee.save(update_fields=['bank_code'])


class Migration(migrations.Migration):

    dependencies = [
        ('payroll', '0011_company_contact_email_company_contact_number'),
    ]

    operations = [
        migrations.AddField(
            model_name='employee',
            name='bank_code',
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
        migrations.AddField(
            model_name='employee',
            name='paystack_recipient_code',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.RunPython(populate_bank_codes, migrations.RunPython.noop),
    ]
