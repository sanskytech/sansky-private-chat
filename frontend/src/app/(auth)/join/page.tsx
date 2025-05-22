'use client';

import Link from "next/link";
import { useState } from "react";
import { useRouter } from "next/navigation";
import TextInputField from "@/components/CustomTextField";
import Button from "@/components/Button";
import { InvitationCodeCheckAction } from "@/actions/action"; // adjust the path if needed

const Page = () => {
  const [username, setUsername] = useState("");
  const [invitationCode, setInvitationCode] = useState("");
  const router = useRouter();

  const onJoinClick = async () => { 
    if (username === "" || invitationCode === "") {
      alert("Please fill all fields");
      return;
    }

    const formData = new FormData();
    formData.append("username", username);
    formData.append("invitecode", invitationCode);

    const response = await InvitationCodeCheckAction({}, formData);

    if (response.success) {
      console.log("response of server after decrypting the qrcode",response );
      router.push(`/waiting?code=${invitationCode}&username=${username}`);
      
    } else {
      alert(response.message || "Invitation failed");
    }

    
  };

  return (
    <div className="relative flex w-full h-full flex-col gap-4 justify-center items-center">
      <div className="w-11/12 md:w-6/12 xl:w-4/12 flex flex-col mt-4 p-4 md:p-10 rounded shadow-xl bg-[#0795c64d]">
        <h2 className="text-center text-white mb-4">Enjoy Security With Sanskytech</h2>

        <TextInputField
          required
          label={"Username"}
          name={"username"}  
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <TextInputField
          required
          label={"Invitation Code"}
          name={"invitecode"}
          value={invitationCode}
          onChange={(e) => setInvitationCode(e.target.value)}
        />

        <div className="flex justify-start mb-2 gap-2">
          <span className="text-xs sm:text-base text-white">Want to Create new one?</span>
          <Link href={'/create'} className="text-xs sm:text-base text-primary">Create Here</Link>
        </div>

        <Button onClick={onJoinClick} label="Join" />
      </div>
    </div>
  );
};

export default Page;
