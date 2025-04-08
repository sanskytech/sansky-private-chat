'use client';

import { useState , useEffect} from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Typography,
  IconButton,
  Slide,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';

const WelcomeDialog = () => {
  const [open, setOpen] = useState(false);


  useEffect(() => {
    const dialogState = localStorage.getItem('wd-closed');
    console.log(dialogState);
    if (dialogState === 'true') {
      setOpen(false);
    }
    else {
      setOpen(true)
    }
  }, []);


  const handleRefresh = () => {
    window.location.reload();
  };

  const handleClose = () => {
    
    setOpen(false);
    localStorage.setItem('wd-closed', 'true');

  };

  // Custom transition wrapper for Slide effect
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const Transition = (props: any) => <Slide /* direction="down " */ {...props} />;

  return (
    <Dialog
      open={open}
      onClose={handleClose}
      keepMounted
      aria-describedby="welcome-description"
      slots={{
        transition: Transition, 
      }}
      slotProps={{
        paper:{
        className: 'rounded-2xl shadow-lg p-4 !relative',
        style: {
          backgroundColor: 'rgba(7, 149, 198, 0.3)',
        },
      },
        backdrop:{
        style: {
          backgroundColor: 'rgba(7, 149, 198, 0.3)',
        },
      }
    }}
    >
      <IconButton
        aria-label="close"
        onClick={handleClose}
        className="!absolute top-2 right-2 text-white"
      >
        <CloseIcon />
      </IconButton>

      <DialogTitle className="text-center text-2xl font-bold text-white">
        Welcome to SanskyTech Private Chat
      </DialogTitle>

      <DialogContent>
        <Typography
          id="welcome-description"
          className="text-white text-sm text-center px-2"
        >
          Currently there is only one person in the room. If you want, you can wait until at least another
          person joins or skip this process. We’ll notify you when someone joins. 
          You can also invite your friends by clicking the Invite Button on the left Pannel.
        </Typography>
      </DialogContent>

      <DialogActions className="justify-center">
        <Button
          variant="contained"
          onClick={handleRefresh}
          className="bg-white text-blue-700 font-semibold px-4 py-2 rounded hover:bg-blue-100"
        >
          Refresh Page
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default WelcomeDialog;
