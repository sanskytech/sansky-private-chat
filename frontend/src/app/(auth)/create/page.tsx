'use client';

import { useActionState, useTransition, useEffect, useState, forwardRef } from "react";
import { useRouter } from "next/navigation";
import { createRoomAction } from "@/actions/action";
import Button from "@/components/Button";
import TextInputField from "@/components/CustomTextField";
import Link from "next/link";
import Snackbar from "@mui/material/Snackbar";
import MuiAlert, { AlertColor } from "@mui/material/Alert";

const initialState = {
  success: false,
  message: "",
  token: undefined,
  userId: undefined,
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const Alert = forwardRef(function Alert(props: any, ref) {
  return <MuiAlert elevation={6} ref={ref} variant="filled" {...props} />;
});




const Page = () => {
  const [state, formAction] = useActionState(createRoomAction, initialState);
  const [isPending, startTransition] = useTransition();
  const [groupName, setGroupName] = useState("");
  const [username, setUsername] = useState("");
  const [snackbar, setSnackbar] = useState({
    open: false,
    message: "",
    severity: "success" as AlertColor,
  });

  const router = useRouter();

  useEffect(() => {
    if (state.message) {
      setSnackbar({
        open: true,
        message: state.message,
        severity: state.success ? "success" : "error",
      });

      if (state.success && groupName) {
        setTimeout(() => {
          router.push(`/chat/${groupName}`);
        }, 1000); // wait for snackbar before redirect
      }
    }
  }, [groupName, router, state]);

  const handleSubmit = (formData: FormData) => {
    setGroupName(formData.get("groupName") as string);
    setUsername(formData.get("username") as string);

    startTransition(() => {
      formAction(formData);
    });
  };

  return (
    <div className="flex w-full h-full flex-col gap-4 justify-center items-center">
      <form action={handleSubmit} className="w-11/12 md:w-6/12 xl:w-4/12 p-4 md:p-10 flex flex-col mt-4 rounded shadow-lg bg-[#0795c64d]">
        <h2 className="text-center text-white mb-4">Enjoy Security With Sanskytech</h2>

        <TextInputField
          label="Username"
          name="username"
          required
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <TextInputField
          label="Groupname"
          name="groupName"
          required
          value={groupName}
          onChange={(e) => setGroupName(e.target.value)}
        />

        <div className="flex justify-start gap-2 mb-2">
          <span className="text-xs sm:text-base text-white">Want to join a group?</span>
          <Link href="/join" className="text-xs sm:text-base text-primary">Join Here</Link>
        </div>

        <Button
          label={isPending ? "Creating..." : "Create Room"}
          type="submit"
          disabled={isPending}
          spinner={isPending}
        />
      </form>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={2000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
        anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
      >
        <Alert onClose={() => setSnackbar({ ...snackbar, open: false })} severity={snackbar.severity}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </div>
  );
};

export default Page;
