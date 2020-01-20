-- 连接onenet后台 上传数据到MQTT里面
-- 用http管理接口 开机注册设备
-- 调用hmac 加密 算出连接密钥

module(...,package.seeall)

require"ntp"
require"misc"
require"utils"
require"ril"
require"http"
require "mqtt"


productsId = "311703" -- 产品ID 
access_key = "2GLOWVxxl1ko/SgkIENQRE42szfXTaqvFM61HlObwt0="

httpApiKey = "" -- 利用时间动态生成的
mqttKey = "" --利用时间动态生成
DevKey = "" -- 利用注册设备函数 在onenet 获取 设备key 信息
DevID = "" --onenet 后台分配的设备ID
--[[
MQTT 相关配置
--]]
local mqttc = ""
local host, port = "183.230.40.16", 8883
local MqClientId = "" -- 硬件IMEI
local MqUserName = productsId
local Mqpassword = ""
-- 基站时间同步成功标志
local bCLTSTimeSyned

local slen = string.len

HeatFlag = 1

--[[
url 编码函数
--]]
local function urlEncode(s)     
    s = string.gsub(s, "([^%w%.%- ])", function(c) 
    return string.format("%%%02X", string.byte(c)) end)    
    return string.gsub(s, " ", "+")
end 
--[[
url 解码函数
--]]
local function urlDecode(s)    
    s = string.gsub(s, '%%(%x%x)', function(h) 
    return string.char(tonumber(h, 16)) end)    
    return s
end
--[[
字符串的十六进制数据转二进制
--]]
local function hex_to_binary(hex)
   return (hex:gsub("..", function(hexval)
      return string.char(tonumber(hexval, 16))
   end))
end
--[[
连接onenet后台 的token 创建函数
参数 et 密钥过期时间点 字符串
     res 实例名称 有API访问的密钥 和设备mqtt 登陆用的密钥
	 access_key 产品key
返回连接用的 密钥
说明：加密方式 为sha1
--]]
local function OnenetTokenCreate(et , res ,access_key)
	-- 密钥时间只能一个小时有效 
	--res = "products/".. tostring(productsId)
	--et = os.time() + 3600
	--et = 1578231806
	method = "sha1"
	version = '2018-10-31'
	org1 = et .. '\n' .. method .. '\n' ..  res .. '\n' .. version
	log.info("org1="..org1)
	key  = crypto.base64_decode(access_key,string.len(access_key)) -- 解码

	sign_b = crypto.hmac_sha1(org1,string.len(org1),key,string.len(key)) -- 采用hmac 里面的sha1 加密算法
	log.info("Hmac_sha1 Hex data = " .. sign_b)
	sign_b = hex_to_binary(sign_b)
	log.info("Hmac_sha1 Hex data2 = " .. sign_b)

	sign = crypto.base64_encode( sign_b, string.len(sign_b) ) -- 对hmac 出来的数据进行 base64 编码

	hmacUrl = urlEncode(sign)
	log.info("经过url 编码的hamc 加密码=" .. hmacUrl)
	resUrl = urlEncode(res) -- res 字符串也 url 编码
	return string.format('version=%s&res=%s&et=%s&method=%s&sign=%s' ,version, resUrl, et, method, hmacUrl) 
end
--[[
TokenGetHttpApiAndMqtt 
获取MQTT 通信用的密钥 和 HTTP API 访问的 API 
--]]
local function TokenGetHttpApiAndMqtt()
	et = tostring( os.time() + 3600 )-- 有效密钥时间一个小时
	res = "products/".. tostring(productsId)
	httpApiKey = OnenetTokenCreate(et,res,access_key)
	res = "products/".. tostring(productsId) .. "/devices/" .. misc.getImei() 
	mqttKey = OnenetTokenCreate(et,res,access_key)
	log.info("httpApiKey=".. httpApiKey)
	log.info("mqttKey=".. mqttKey)
	MqClientId = misc.getImei() 
	Mqpassword = httpApiKey -- 正常应该是设备KEY  有BUG
end
--[[
 时间同步优先使用 基站同步
 基站同步失败后考虑 系统里面的免费ntp同步
 --]]
--发送AT+CLTS=1，打开基站同步时间功能
ril.request("AT+CLTS=1")
--注册基站时间同步的URC消息处理函数
ril.regUrc("*PSUTTZ", function() 
	local tm = misc.getClock()
	log.info("基站时间同步完成 当前时间", string.format("%04d/%02d/%02d,%02d:%02d:%02d", tm.year, tm.month, tm.day, tm.hour, tm.min, tm.sec))
	log.info("当前秒时间数值=",os.time())   
	-- 计算出 http api key  mqtt key
	TokenGetHttpApiAndMqtt()
	bCLTSTimeSyned = true 
end)

-- 时间同步完成回调函数
local function TimeSyncFun()
	if ntp.isEnd() == true then
		local tm = misc.getClock()
		log.info("ntp 网络时间同步成功", string.format("%04d/%02d/%02d,%02d:%02d:%02d", tm.year, tm.month, tm.day, tm.hour, tm.min, tm.sec))
		log.info("当前秒时间数值=",os.time())
		-- 计算出 http api key  mqtt key
		TokenGetHttpApiAndMqtt()
	else 
		
	end
end
--[[
[2020-01-12 12:06:01.524]: [I]-[testHttp.cbFnc]	true	200
[2020-01-12 12:06:01.533]: [I]-[testHttp.cbFnc]	Transfer-Encoding: chunked
[2020-01-12 12:06:01.542]: [I]-[testHttp.cbFnc]	Content-Type: application/json;charset=UTF-8
[2020-01-12 12:06:01.553]: [I]-[testHttp.cbFnc]	Date: Sun, 12 Jan 2020 04:06:01 GMT
[2020-01-12 12:06:01.565]: [I]-[testHttp.cbFnc]	Pragma: no-cache
[2020-01-12 12:06:01.576]: [I]-[testHttp.cbFnc]	Connection: keep-alive
[2020-01-12 12:06:01.585]: [I]-[testHttp.cbFnc]	bodyLen=242

--]]
local function cbFnc(result,prompt,head,body)
    log.info("testHttp.cbFnc",result,prompt)
    if result and head then
        for k,v in pairs(head) do
            log.info("testHttp.cbFnc",k..": "..v)
        end
    end
    if result and body then
        log.info("testHttp.cbFnc","bodyLen="..body:len())
		log.info("testHttp body="..body)
		local tjsondata,result,errinfo = json.decode(body)
		if result and type(tjsondata)=="table" then
			log.info("onenet http recv " .. "code_no",tjsondata["code_no"])
			log.info("onenet http recv " .. "code",tjsondata["code"])
			log.info("onenet http recv " .. "message",tjsondata["message"])
			log.info("onenet http recv " .. "data",tjsondata["data"])
			--log.info()
			tjsondata2 = tjsondata["data"]

			log.info("onenet http recv data " .. "key",tjsondata2["key"])
			log.info("onenet http recv data " .. "device_id",tjsondata2["device_id"])
			DevKey = tjsondata2["key"]
			DevID = tjsondata2["device_id"] 

		else
			log.info("testJson.decode error",errinfo)
		end
    end
    
end

--[[
向onenet 平台注册设备的https 请求
数据发送出去必须等待 回调函数 发送消息回来
这个函数必须是在协程里面调用 应该发送出去之后需要阻塞等待
--]]
local function OnenetRegDev(IMEI)
	SendData={
		name = IMEI,
		desc = "硬件设备利用IMEI注册",
	}
	SendDataJson = json.encode(SendData)
	log.info("发送出去的body JSON="..SendDataJson)
	http.request("POST","http://api.heclouds.com/mqtt/v1/devices/reg",nil,
         {["Authorization"]=httpApiKey ,["Content-Type"]="application/json" },
         {[1]=SendDataJson},
         50000,cbFnc)
end

--[[
推送数据到 Onenet 的数据流模板里面里面 
template

{
    "id": 123,        
    "dp": {             
        "temperatrue": [{     
            "v": 30,       
            "t": 1552289676
        }],
        "power": [{     
            "v": 4.5,        
            "t": 1552289676 
        }],
        "status": [{
                "v": {
                    "color": "blue"
                },
                "t": 1552289677
            },
            {
                "v": {
                    "color": "red"
                },
                "t": 1552289678
            }
        ]
    }
}

--]]
local function OnenetSendMqttDataT(  ComId ,WenduValue, Vbat , ChongNumber , lonv , latv , elev , QoS )
	timePoint = os.time()
	Data = {
		id = ComId ,
		dp = {
			WenDu = {
				{
				v = WenduValue ,
				t = timePoint ,
				}
			},
			power ={
				{
				v = Vbat ,
				t = timePoint,
				}
			},
			ChongData = {
				{
				v = ChongNumber ,
				t = timePoint ,
				}
			},
			--[[
			location ={
				{
				lon = lonv ,
				lat = latv ,
				--ele = elev ,
				}
			},
			--]]
			
		} ,
	}
	JsonData = json.encode(Data)
	log.info(" OnenetSendMqttDataT Send " .. JsonData)
	publishDataDp = string.format("$sys/%s/%s/dp/post/json",productsId,MqClientId)
	log.info(" publishDataDp " .. publishDataDp)
	mqttc:publish(publishDataDp,JsonData,QoS)
end
-- 连接后台函数
local function OnenetConnect()
	local ComId = 0
	WaitTimeCut = 0
	log.info("等待时间同步")
	while true do 
		if bCLTSTimeSyned == true then 
			log.info("基站时间同步成功")
			break 
		else
			log.info("等待时间同步中.....")
			WaitTimeCut = WaitTimeCut + 1 
			if WaitTimeCut >= 100 then -- 基站时间同步失败
				if ntp.isEnd() == true then 
					log.info("网络ntp 同步成功")
					break 
				else
				end
				
			end
		end
		sys.wait(600)
		if WaitTimeCut >= 600000 then -- 这里等待时间超过10分钟重启
			rtos.restart()
		end
	end
	-- 等待TCP 环境准备好
	while not socket.isReady() do sys.wait(1000) end
	OnenetRegDev(misc.getImei()) --- 在onenet 后台注册设备 或者获取信息
	log.info("等待 设备信息注册完成")
	sys.wait(10000) -- 临时添加 避免 没有获取到设备信息的BUG 后面考虑阻塞等待消息
	mqttc = mqtt.client(MqClientId, 300, MqUserName, Mqpassword)
	log.info("mqtt.client MqClientId ".. MqClientId .. " MqUserName " .. MqUserName .. "  Mqpassword " .. Mqpassword .. " host " .. host .. " port " .. tostring(port) )
	if mqttc:connect(host, port,"tcp_ssl",{clientCert="certificate.pem"}) ==  true then 
	--if mqttc:connect("183.230.40.96",1883,"tcp") == true then 
		log.info("连接MQTT成功")
		log.info("MQTT CON OK ")
	else 
		log.info("连接MQTT失败")
		log.info("MQTT CON ERR ")
	end
	--sys.wait(10000)
	--while not mqttc:connect(host, port,"tcp") do sys.wait(2000) log.info("mqtt.client MqClientId ".. MqClientId .. " MqUserName " .. MqUserName .. "  Mqpassword " .. Mqpassword .. " host " .. host .. " port " .. tostring(port) ) end --,"tcp_ssl",{clientCert="certificate.pem"} 
	-- 订阅消息 
	SubscribeAccepted = string.format("$sys/%s/%s/dp/post/json/accepted",productsId,MqClientId)
	SubscribeRejected = string.format("$sys/%s/%s/dp/post/json/rejected",productsId,MqClientId)
	SubscribeCmdAll = string.format("$sys/%s/%s/cmd/request/#",productsId,MqClientId)


	log.info(" SubscribeAccepted " .. SubscribeAccepted)
	mqttc:subscribe(SubscribeAccepted) -- $sys/{pid}/{device-name}/dp/post/json/accepted 数据节点上传成功
	--sys.wait(10000)
	log.info(" SubscribeRejected " .. SubscribeRejected)
	mqttc:subscribe(SubscribeRejected)-- $sys/{pid}/{device-name}/dp/post/json/rejected 数据节点上传失败
	--sys.wait(10000)
	log.info(" SubscribeCmdAll " .. SubscribeCmdAll)
	mqttc:subscribe(SubscribeCmdAll)
	--sys.wait(10000)
	
	while true do
		local r, data, param = mqttc:receive(50, "pub_msg")
		if r then
			log.info("这是收到了服务器下发的消息:", data.payload or "nil")
		elseif data == "pub_msg" then
			log.info("这是收到了订阅的消息和参数显示:", data, param)
			--mqttc:publish(string.format("/device/%s/resp", misc.getImei()), "response " .. param)
		elseif data == "timeout" then
			--log.info("这是等待超时主动上报数据的显示!")
			--mqttc:publish(string.format("/device/%s/report", misc.getImei()), "test publish " .. os.time())
		else
			break
		end
		
		if HeatFlag == 1 then
			HeatFlag = 0 
			OnenetSendMqttDataT(  ComId ,10, 36 , 2 , 100 , 100 , 2 , 1 )
			ComId = ComId + 1 
		end 
	end
	
	
end
function HeatCallFun()
	HeatFlag = 1
end
ntp.timeSync(100,TimeSyncFun) -- 10分钟 同步一次 ntp 时间
sys.taskInit(OnenetConnect)
sys.timerLoopStart(HeatCallFun, 40000) -- 40000 40 秒钟
--[[
-- 做hmac_sha1 测试的函数
local function hmac_sha1Test()
	message = "1578231806\nsha1\nproducts/310259\n2018-10-31" 
	key= "HX0FpvjQIqd4V76Zef6LnaetjJN3p9iDIEPrUDSsOa4=" 
	log.info("----------------------------------------------------------")
	log.info("message data ="..message)
	log.info("message len=".. tostring(string.len(message)))
	log.info("key data ="..key)
	log.info("key len=".. tostring(string.len(key)))
	log.info("----------------------------------------------------------")
	sign_b = crypto.hmac_sha1(message,string.len(message),key,string.len(key)) -- 采用hmac 里面的sha1 加密算法
	log.info("Hmac_sha1 Hex data = " .. sign_b)
	log.info("sign_b raw =" .. hex_to_binary(sign_b) )
	log.info("sign_b raw =" .. string.toHex(hex_to_binary(sign_b)))
end
--hmac_sha1Test()
--]]
