local multipart = require("multipart")
local urlencode = require('urlencode')

local plugin = {
  PRIORITY = 1000, -- set the plugin priority, which determines plugin execution order
  VERSION = "0.1", -- version in X.Y.Z format. Check hybrid-mode compatibility requirements.
}

-- runs in the 'access_by_lua_block'
function plugin:access(plugin_conf)
  local initialRequest = kong.request.get_raw_body()
  local sql_pattern_list = {"[%s]*(delete)", "[%s]*(exec)", "[%s]*(drop)", "[%s]*(insert)", "[%s]*(shutdown)", "[%s]*(update)", "[%s]* or ", " or$", "^or "}

  local code_pattern_list = {".*exception in thread.*", "[%s]*(<%s*script%f[^>]*>[^<]+<%s/*%s*script%s*>)", "[%s]*(include)", "[%s]*(exec)", "[%s]*(echo)", "[%s]*(config)", "[%s]*(printenv)", "[%s]*(/?ancestor(-or-self)?)", "[%s]*(/?descendant(-or-self)?)", "[%s]*(/?following(-sibling))", "[%s]* or ", " or$", "^or "}

  function injection(parameter_list)
      for key,value in pairs(parameter_list) do
          for pattern = 1, #code_pattern_list do
              if string.match(string.lower(tostring(value)), code_pattern_list[pattern]) then
                  local error_response = {
                      success = "false",
                      status = "failed",
                      errorCode = "8004",
                      message = "Code Injection Detected"}
                  return kong.response.exit(400, error_response, {
                      ["Content-Type"] = "application/json"
                  })
              end
          end
          for pattern = 1, #sql_pattern_list do
              if string.match(string.lower(tostring(value)), sql_pattern_list[pattern]) then
                  local error_response = { 
                              success = "false",
                              status = "failed",
                              errorCode = "8005",
                              message = "SQL Attack Detected"
                          }
                  return kong.response.exit(400, error_response, {
                      ["Content-Type"] = "application/json"
                  })
              end
          end
      end
  end


  if type(initialRequest) ~= "nil" and initialRequest ~= ""  then

          local query_param_list = kong.request.get_query()
          local header_list = kong.request.get_headers()
          local content_type = kong.request.get_header("content-type")

          -- checking injection in the query parameter
          injection(query_param_list)
          injection(header_list)

          if string.match(content_type, "multipart/form%-data") then
              local request_body = multipart(kong.request.get_raw_body(), kong.request.get_header("Content-Type")):get_all() 
              injection(request_body)
          end

          if string.match(content_type, "application/x%-www%-form%-urlencoded") then
              local request_body = {}
              local flag = false
              local temp;
              for pair in string.gmatch(initialRequest, "([^&]+)") do
                  for res in string.gmatch(pair, "([^=]+)") do
                      if flag then
                      request_body[urlencode.decode_url(temp)] = urlencode.decode_url(res)
                      flag = false
                      else
                          temp = res
                          flag = true
                      end
                  end
              end
              injection(request_body)
          end
  else
      local error_response = {
          message =  "request body validation failed with error: 'received empty request body'",
          }
      return kong.response.exit(400, error_response, {
          ["Content-Type"] = "application/json"
      })
  end

end --]]

-- return our plugin object
return plugin
