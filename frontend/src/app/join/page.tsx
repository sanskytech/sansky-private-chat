
import { TextField } from "@mui/material";
import Link from "next/link";

const Page = () => {
    return (
      <div className="relative flex w-full h-full flex-col gap-4 justify-center items-center">
        {/* Logo positioned at top-left */}

        
  
        {/* Page Content */}
        <div className="flex flex-col gap-8 mt-4 p-10 bg-white rounded shadow-xl w-2/3 xl:w-4/11 " style={{ backgroundColor: 'rgba(7, 149, 198, 0.3)' }} >
          
          <h2 className="text-center">Enjoy Security With Sanskytech</h2>
          <TextField
  required
  id="outlined-required"
  label="Username"
  className="rounded-xl"
  sx={{
    backgroundColor: 'white',
    '& .MuiOutlinedInput-root': {
      borderRadius: '12px', // Same as your rounded-xl input
      '& fieldset': {
        borderColor: '#0795C6', // Default border color
        borderRadius: '12px', // Ensure the fieldset matches the rounded corners
      },
      '&:hover fieldset': {
        borderColor: '#0795C6', // Border on hover
      },
      '&.Mui-focused fieldset': {
        borderColor: '#0795C6', // Border when focused
      },
    },
  }} 
/>

<TextField
  required
  id="outlined-required"
  label="Invitation Code"
  className="rounded-xl"
  sx={{
    backgroundColor: 'white',
    '& .MuiOutlinedInput-root': {
      borderRadius: '12px', // Same as your rounded-xl input
      '& fieldset': {
        borderColor: '#0795C6', // Default border color
        borderRadius: '12px', // Ensure the fieldset matches the rounded corners
      },
      '&:hover fieldset': {
        borderColor: '#0795C6', // Border on hover
      },
      '&.Mui-focused fieldset': {
        borderColor: '#0795C6', // Border when focused
      },
    },
  }}
/>


          <div className="flex justify-start gap-2">
            <span  className="text-white" >Want to Create new one?</span>
            <Link href={'/create'} className="text-primary">Create Here</Link>
          </div>

          <button className="text-white font-bold py-2 px-4 rounded-xl" style={{ backgroundColor: "#2F98BC"}}>
            Join
          </button>
          </div>
      </div>
    );
  }
  
  export default Page;
  

  