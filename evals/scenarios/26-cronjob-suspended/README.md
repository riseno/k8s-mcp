# 26 Suspended CronJob

The CronJob runs every minute but `suspend: true` stops it from creating Jobs.

Expected: `cronjob.not_scheduling`, pointing at `suspend`.
