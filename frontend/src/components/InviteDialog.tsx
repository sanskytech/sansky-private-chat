'use client';

import {  useEffect, useRef, useState } from 'react';
import { Dialog, DialogTitle, DialogContent, DialogActions, Button, IconButton, Typography } from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import QRCodeStyling from 'qr-code-styling';
import { generateRandomKey } from '@/utils/utils';

type InviteDialogProps = {
  onInviteDialogClose?: () => void;
  open: boolean;
} 


const InvitaDialog = ({onInviteDialogClose, open}:InviteDialogProps) => {
  // const [open, setOpen] = useState(false); 

  const qrRef = useRef<HTMLDivElement | null>(null); // Reference for the QR code container
  const [invitationCode, setInvitationCode] = useState(generateRandomKey()); // Example code (this could be fetched from a backend)

  useEffect(() => {
    if (!open) return; // Prevent issues if qrRef is null or dialog is closed

    const timer = setTimeout(() => {
      console.log('Generating QR code...');
      
      const qrCode = new QRCodeStyling({
        width: 200,
        height: 200,
        data: invitationCode, // This is the text inside the QR code
        dotsOptions: {
          color: '#2F98BC', // QR Code color
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
      if (qrRef.current === null) return; // Check if qrRef is not null
      qrCode.append(qrRef.current); // Append the QR code (this renders it)

    }, 1000); // Delay by 1 second

    return () => clearTimeout(timer); // 

  }, [open, invitationCode]); 


  const handleClose = () => {
    // setOpen(false); // Close the dialog
    if (onInviteDialogClose !== undefined) {
      onInviteDialogClose();
    }
  };

  const handleRefresh = () => {
    // clear the qrRef Div
    if (qrRef.current) {
      qrRef.current.innerHTML = '';
    }
    // Refresh the invitation code
    setInvitationCode(generateRandomKey());

  };

  const handleCopyButton = () => {
    if (typeof window !== 'undefined' && navigator.clipboard) {
      navigator.clipboard.writeText(invitationCode)
        .then(() => alert('Code copied to clipboard!'))
        .catch((error) => console.error('Failed to copy:', error));
    } else {
      // Fallback method for unsupported environments
      const textArea = document.createElement('textarea');
      textArea.value = invitationCode;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy'); // Old-school method
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
      navigator.share(shareData)
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
