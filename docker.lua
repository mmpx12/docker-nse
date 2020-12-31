author = "Dr Claw"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery"}

description = [[ List active docker containers ]]

--
-- @output
-- docker:
--   active containers:
--     IMAGE: alpine
--       -- COMMAND: /bin/sh
--       -- UPTIME: 25 minutes
--       -- ENV:
--         - VAR1=var
--         - VAR2=var2
-- 

local nmap = require "nmap"
local stdnse = require "stdnse"
local http = require "http"
local json = require "json"

portrule = function(host,port)
  if port.service == "docker" or port.number == "2375" or
  port.service == "docker-s" or port.number == "2376" then
    return true
  end
end

action = function(host, port)
  local output = stdnse.output_table()
  output.Running_containers = {}
  cont = http.get(host, port.number, "/containers/json")
  if string.match(cont.rawbody, "Client sent an HTTP request to an HTTPS server.") then
    output = "Look's like --tlsverify flag is set"
  else 
    if cont.status == 200 then
      resp, data = json.parse(cont.body)
      if resp then
        for key,value in pairs(data) do
          output.Running_containers[#output.Running_containers +1] =  "IMAGE: " ..
            string.gsub(data[key]["Image"],"@sha256:.*", "") .. "\n      -- COMMAND: " ..
            data[key]["Command"] .. "\n      -- UPTIME: " .. string.gsub(data[key]["Status"], "Up ", "", 1)
          content = http.get(host, port.number, "/containers/".. data[key]["Id"] .."/json")
          if content.status == 200 then
          response, datas = json.parse(content.body)
            if resp then
              for keyz, valuez in pairs(datas["Config"]) do
                if keyz == "Env" and #valuez > 1 then
                  output.Running_containers[#output.Running_containers] = output.Running_containers[#output.Running_containers] ..
                    "\n      -- ENV: "
                  for k, v in pairs(valuez) do
                    if not string.match(v, "PATH=") then
                      output.Running_containers[#output.Running_containers] = output.Running_containers[#output.Running_containers] ..
                        "\n        - " .. v
                    end
                  end
                end
              end
            end
          end    
        end
      end
    end
  end
  if #output < 2 then 
    if #output.Running_containers == 0 then
        output = "\n  No containers are running .."
    end
  end
  return output
end
