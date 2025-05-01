'use client';

import { useEffect, useRef, useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  IconButton,
  Typography,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import QRCodeStyling from 'qr-code-styling';

// import { generateRandomKey } from '@/utils/utils';

type InviteDialogProps = {
  onInviteDialogClose?: () => void;
  open: boolean;
  invitationcode: string
};

const InvitaDialog = ({ onInviteDialogClose, open }: InviteDialogProps) => {
  const qrRef = useRef<HTMLDivElement | null>(null);
  const [invitationCode, setInvitationCode] = useState('');

  useEffect(() => {
    if (!open) return;

    
  }, [open]);

  useEffect(() => {
    if (!open || !invitationCode || !qrRef.current) return;

    const qrCode = new QRCodeStyling({
      width: 200,
      height: 200,
      data: invitationCode,
      dotsOptions: {
        color: '#2F98BC',
        type: 'rounded',
      },
      backgroundOptions: {
        color: '#ffffff',
      },
      imageOptions: {
        crossOrigin: 'anonymous',
        margin: 10,
      },
    });

    qrRef.current.innerHTML = '';
    qrCode.append(qrRef.current);

    return () => {
      if (qrRef.current) {
        qrRef.current.innerHTML = '';
      }
    };
  }, [open, invitationCode]);

  const handleClose = () => {
    if (onInviteDialogClose) {
      onInviteDialogClose();
    }
  };

  const handleRefresh = async () => {
    if (qrRef.current) {
      qrRef.current.innerHTML = '';
    }
    try {
      
    } catch (error) {
      console.error('Error refreshing code:', error);
    }
  };

  const handleCopyButton = () => {
    if (typeof window !== 'undefined' && navigator.clipboard) {
      navigator.clipboard
        .writeText(invitationCode)
        .then(() => alert('Code copied to clipboard!'))
        .catch((error) => console.error('Failed to copy:', error));
    } else {
      const textArea = document.createElement('textarea');
      textArea.value = invitationCode;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
      alert('Code copied to clipboard!');
    }
  };

  const handleShareButton = () => {
    const shareData = {
      title: 'Join SanskyChat',
      text: `Hey! Join me on SanskyChat with this code: ${invitationCode}`,
      url: `${window.location.origin}/join`,
    };

    if (navigator.share) {
      navigator
        .share(shareData)
        .then(() => console.log('Shared successfully'))
        .catch((error) => console.error('Error sharing:', error));
    } else {
      alert('Sharing is not supported on this browser. Please copy the code manually.');
    }
  };

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
      <div className="relative">
        <IconButton
          aria-label="close"
          onClick={handleClose}
          className="!absolute top-2 right-2 text-black"
        >
          <CloseIcon />
        </IconButton>

        <DialogTitle className="text-center text-2xl font-bold text-[#0795c6]">
          Invitation Code
        </DialogTitle>

        <DialogContent>
          <div ref={qrRef} className="flex justify-center mb-4" />

          <Typography className="text-center text-sm sm:text-base text-black mb-4">
            Do not share the secret code with an unknown person!
          </Typography>

          <div className="flex justify-center items-center gap-4">
            <Button
              variant="contained"
              color="primary"
              onClick={handleCopyButton}
              className="flex-1 text-white"
            >
              Copy Code
            </Button>

            <Button
              variant="contained"
              color="primary"
              onClick={handleShareButton}
              className="flex-1 text-white"
            >
              Share Code
            </Button>
          </div>
        </DialogContent>

        <DialogActions className="justify-center">
          <Button onClick={handleRefresh} variant="outlined" color="primary">
            Refresh the code
          </Button>
        </DialogActions>
      </div>
    </Dialog>
  );
};

export default InvitaDialog;
