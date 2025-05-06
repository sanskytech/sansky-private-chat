"use server";

import { cookies } from 'next/headers'

import axios, { AxiosError } from "axios";
import { generateECDHKeyPair } from '@/utils/utils';



export async function getCookie(name: string) {
  const cookieStore = await cookies();
  const cookieValue = cookieStore.get(name)?.value || null;
  return cookieValue;
}



const api = axios.create({
    baseURL: process.env.API_URL, // Ensure this is set in your environment variables
    withCredentials: true,           // Ensure cookies (including HTTP-only) are sent
  });


interface InvitationCodeCheckResponse{
  inviter_id: string;
  group_name: string;
  new_user: string;
  message: string;

}

interface InvitationCodeResponse {
  invitation_code: string;
}

interface CreateRoomResponse {
  encrypted_data: string;
  user_id: string;
}

interface ActionState {
  success: boolean;
  message: string;
  token?: string;
  userId?: string;
}

export async function InvitationCodeCheckAction(
  prevState: ActionState,
  formData: FormData
): Promise<ActionState> {
  const username=formData.get("username") as string;
  const invitation_code=formData.get("invitecode") as string;

  try {
    const response=await api.post<InvitationCodeCheckResponse>(
      "/invitation-code-check",
      {
        username: username,
        invitation_code: invitation_code,
      },
      {
        headers:{
          "Content-Type": "application/json",
        },
      }
    );


    const data=response.data;
    if (response.status == 200){
      const newUserName=data.new_user;
      const groupName=data.group_name;
      const inviterid=data.inviter_id;
      const message=data.message;
      return {
        success: true,
        message: message,
        inviterGroup: groupName,
        inviterId: inviterid,
        newusername: newUserName,

      };
      
    }
    else {
      return {
        success:false,
        message: response.statusText,
      };
    }
  } catch (error:unknown){
    const axiosError= error as AxiosError<{ message?: string }>;
    const errorMessage= axiosError.response?.data?.message || axiosError.message ||"Something went Wrong";
  }
  return {
    success: false,
    message: errorMessage,
  };
}






export async function InvitationCodeAction(
): Promise<ActionState> {
  const cookieValue = await getCookie("auth_token");

  try {
    const response = await api.post<InvitationCodeResponse>(
      "/invitation-code-generation",
      {},
      {
        headers: {
          Authorization: `Bearer ${cookieValue}`,
        },
      }
    );

    const data = response.data;

    if (response.status == 200) {
      const inviteCode = data.invitation_code;

      return {
        success: true,
        message: "The invitation code was received successfully.",
        // Optionally return the code as token:
        token: inviteCode,
      };
    } else {
      return {
        success: false,
        message: "The invitation code was not received.",
      };
    }

  } catch (error: unknown) {
    const axiosError = error as AxiosError<{ message?: string }>;
    const errorMessage =
      axiosError.response?.data?.message || axiosError.message || "Something went wrong";

    return {
      success: false,
      message: errorMessage,
    };
  }
}




export async function createRoomAction(
  prevState: ActionState,
  formData: FormData
): Promise<ActionState> {
  const username = formData.get("username") as string;
  const groupName = formData.get("groupName") as string;

  try {
    const response = await api.post<CreateRoomResponse>(
      "/get-token",
      {
        name: username,
        Group_Name: groupName,
      },
      {
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
    const mymyCookie = await getCookie("auth_token");

    const data = response.data;

    if (response.status == 200) {

        // set http only cockie on the browser
        const cookieStore = await cookies()
        cookieStore.set(
        'auth_token',
        data.encrypted_data,
         {
          httpOnly: true,
          maxAge: 3600,
          sameSite:"lax",
         }
      
        );

       

        // create public and private key
        const { privateKey, publicKey } = generateECDHKeyPair();

        // create a common key on the browser and store it in the indexedDB
        // const commonKey = crypto.getRandomValues(new Uint8Array(16));
        // await indexedDBHelper.storeCommonKey(key, commonKey);
        // await indexedDBHelper.storeUserId(groupName, data.user_id);
        // await indexedDBHelper.storeGroupName(groupName, groupName);
        // await indexedDBHelper.storeUsername(groupName, username);


        return {
            success: true,
            message: "Room created successfully!",
            // token: data.encrypted_data,
            userId: data.user_id,
        };
    }
    else {
        return {
            success: false,
            message: response.statusText,
        };
    }

  } catch (error: unknown) {
    const axiosError = error as AxiosError<{ message?: string }>;
    const errorMessage = axiosError.response?.data?.message || axiosError.message || "Something went wrong";

    return {
      success: false,
      message: errorMessage,
    };
  }
}


