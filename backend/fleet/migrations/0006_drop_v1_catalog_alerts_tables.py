from django.db import migrations

# The v1 apps catalog and alerts were removed together with the v1 dashboard.
# Their tables are no longer read by anything and v2 rebuilds its state from the
# first scan (no data migration of v1 findings, spec section 9 step 4), so they
# are dropped instead of being left orphaned. Children before parents so that
# no CASCADE is needed; IF EXISTS keeps this a no-op on fresh databases.
V1_TABLES = [
    "rollouts_rolloutstep",
    "rollouts_rolloutplan",
    "catalog_vulnerabilityfinding",
    "catalog_hosttarget",
    "catalog_gittarget",
    "catalog_servicegroup",
    "alerts_alertfingerprint",
]


class Migration(migrations.Migration):

    dependencies = [
        ("fleet", "0005_container_suggested_project"),
    ]

    operations = [
        migrations.RunSQL(
            [f"DROP TABLE IF EXISTS {table}" for table in V1_TABLES],
            reverse_sql=migrations.RunSQL.noop,
        ),
    ]
