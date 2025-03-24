import InputField from "@/components/InputField"
import MessageList from "@/components/MessageList"


const ChatPage = () => {
    return (
        <div className="relative flex flex-col h-screen w-full">
            {/* top band */}
            <div className={`absolute top-0 left-0 bg-[#4BA6CB]  w-full h-[75px] z-10 `}>
                <h1 className="text-4xl font-bold text-white text-center">ChatName</h1>
            </div>
            {/* body */}
            <div className="flex-1 overflow-y-scroll bg-gray-100 pt-[100px] mb-[60px]">
                {/* MessageList */}
                <MessageList/> 
            </div>

            {/* bottom band */}
            <div className="absolute bottom-4 left-0 px-4 w-full h-[50px] z-10">
            <InputField />
            </div>        
        </div>
    )
}

export default ChatPage

