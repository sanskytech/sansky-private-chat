import SendIcon from '@mui/icons-material/Send';


const InputField = () => {
    return (
        <div className="flex flex-row bg-white rounded-xl w-full h-full items-center rounded-xl">
        <input
            type="text"
            placeholder="Type a message"
            className={`p-2 border border-gray-300 font-semibold text-lg
                        rounded-md w-11/12 outline-none border-hidden  
                        focus:outline-none`}
        />
        <button className="bg-primary text-white p-2 rounded-xl h-full w-1/12 cursor-pointer" >
            <SendIcon />
        </button>
        </div>
    );
};

export default InputField;