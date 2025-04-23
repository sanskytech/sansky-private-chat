import axios from 'axios';

export const seda=console.log(`${process.env.API_URL}/invitation-code-generation`);

export const fetchInvitationCode = async (): Promise<string> => {
const response = await axios.post(
 `${process.env.NEXT_PUBLIC_API_URL}/invitation-code-generation`,
    {},
    { withCredentials: true } // Auth cookie sent automatically
  );

  return response.data.invitation_code;
};
