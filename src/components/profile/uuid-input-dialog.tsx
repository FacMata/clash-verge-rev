import { TextField } from "@mui/material";
import { forwardRef, useImperativeHandle, useState } from "react";
import { useTranslation } from "react-i18next";

import { BaseDialog } from "@/components/base";

export interface UuidInputDialogRef {
  open: (url: string) => Promise<string | null>;
}

export const UuidInputDialog = forwardRef<UuidInputDialogRef>((_, ref) => {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [uuid, setUuid] = useState("");
  const [url, setUrl] = useState("");
  const [resolver, setResolver] = useState<
    ((value: string | null) => void) | null
  >(null);

  useImperativeHandle(ref, () => ({
    open: (inputUrl: string) => {
      setUrl(inputUrl);
      setUuid("");
      setOpen(true);
      return new Promise<string | null>((resolve) => {
        setResolver(() => resolve);
      });
    },
  }));

  const handleClose = () => {
    setOpen(false);
    resolver?.(null);
    setResolver(null);
  };

  const handleOk = () => {
    const trimmedUuid = uuid.trim();
    if (!trimmedUuid) {
      return;
    }
    setOpen(false);
    resolver?.(trimmedUuid);
    setResolver(null);
  };

  return (
    <BaseDialog
      open={open}
      title={t("profiles.modals.uuidInput.title")}
      contentSx={{ width: 375, pb: 0 }}
      okBtn={t("shared.actions.import")}
      cancelBtn={t("shared.actions.cancel")}
      disableOk={!uuid.trim()}
      onClose={handleClose}
      onCancel={handleClose}
      onOk={handleOk}
    >
      <TextField
        fullWidth
        size="small"
        margin="normal"
        variant="outlined"
        label={t("profiles.modals.uuidInput.fields.url")}
        value={url}
        disabled
        sx={{ mb: 2 }}
      />
      <TextField
        fullWidth
        size="small"
        margin="normal"
        variant="outlined"
        autoFocus
        label={t("profiles.modals.profileForm.fields.subscriptionUuid")}
        placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        helperText={t("profiles.modals.uuidInput.hint")}
        value={uuid}
        onChange={(e) => setUuid(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && uuid.trim()) {
            handleOk();
          }
        }}
      />
    </BaseDialog>
  );
});

UuidInputDialog.displayName = "UuidInputDialog";
