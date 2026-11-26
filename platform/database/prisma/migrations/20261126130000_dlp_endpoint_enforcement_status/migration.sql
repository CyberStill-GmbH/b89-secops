BEGIN;

ALTER TABLE "dlp_endpoints"
  ADD COLUMN "usb_control_status" TEXT,
  ADD COLUMN "usb_control_code" TEXT,
  ADD COLUMN "usb_control_checked_at" TIMESTAMPTZ(3),
  ADD CONSTRAINT "dlp_endpoints_usb_control_status_valid" CHECK (
    "usb_control_status" IS NULL OR "usb_control_status" IN
      ('disabled', 'active', 'pending', 'unsupported', 'conflict', 'error', 'not-applicable')
  ),
  ADD CONSTRAINT "dlp_endpoints_usb_control_code_bounded" CHECK (
    "usb_control_code" IS NULL OR char_length("usb_control_code") <= 64
  );

COMMIT;
