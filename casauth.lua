-- require('print_r')
json = require('json')

-- https://gist.github.com/liukun/f9ce7d6d14fa45fe9b924a3eed5c3d99
local char_to_hex = function(c)
  return string.format("%%%02X", string.byte(c))
end
function urlencode(url)
  if url == nil then
    return
  end
  url = url:gsub("\n", "\r\n")
  -- url = url:gsub("([^%w ])", char_to_hex)
  url = url:gsub("([^%w _%%%-%.~])", char_to_hex)
  url = url:gsub(" ", "+")
  return url
end

function action_casauth(txn)

    -- no GET, do nothing
    if txn.f:method() ~= 'GET' then
        return
    end

    local path = txn.f:path()
    core.Debug('CASAUTH: path = ' .. path)
    local query = txn.f:query()
    if not query then
        query = ''
    end
    core.Debug('CASAUTH: query = ' .. query)

    -- reset
    txn.CAS = {
        user = nil,
        version = optVersion,
        attrs = {}
    }
    if optHeaderPrefix then
        for h,_ in pairs(txn.http:req_get_headers()) do
            if h:sub(1, #optHeaderPrefix) == optHeaderPrefix then
                txn.http:req_del_header(h)
            end
        end
    end

    local query_parameters = core.tokenize(query, '&')
    
    -- bypass
    local bypass = false
    local i
    for j,p in ipairs(query_parameters) do
        if p == optBypassParameter then
            bypass = true
            i = j
            break
        end
    end
    if bypass and not optBypassKeep then
        table.remove(query_parameters, i)
    end
    core.Debug('CASAUTH: bypass = ' .. tostring(bypass) .. ', keep=' .. tostring(optBypassKeep))
    txn.CAS.bypass = bypass
    
    -- ticket
    local ticket = nil
    for j,p in ipairs(query_parameters) do
        p = core.tokenize(p, '=')
        if p[1] == 'ticket' then
            ticket = p[2]
            i = j
        end
    end
    if ticket then
        table.remove(query_parameters, i)
    end

    -- rewrite query
    query = table.concat(query_parameters, '&')
    core.Debug('CASAUTH: sanitized query = ' .. query)
    txn.http:req_set_query(query)

    if not bypass then
        if query ~= '' then
            query = '?' .. query
        end
        local service_url = optServiceUrlPrefix .. path .. query
        core.Debug('CASAUTH: service url = ' .. service_url)
        service_url = urlencode(service_url)
        if not ticket then
            -- phase 1, redirect to login
            local redirect_to = optCasUrlPrefix .. '/login?service=' .. service_url
            if optRenew then
                redirect_to = redirect_to .. '&renew'
            end
            core.Debug('CASAUTH: [1]: redirect to: ' .. redirect_to)
            redirect_to = txn:reply{
                status  = 302,
                headers = {
                    ["location"]  = { redirect_to }
                }
            }
            txn:done(redirect_to)
        else
            -- phase 2, validate ticket
            core.Debug('CASAUTH: [2]: ticket: ' .. ticket)
            local validate_url = optCasUrlPrefix .. cas_validate_url
            validate_url = validate_url .. '?service=' .. service_url .. '&ticket=' .. ticket
            if optRenew then
                validate_url = validate_url .. '&renew'
            end
            if optVersion > 1 then
                validate_url = validate_url .. '&format=JSON'
            end
            core.Debug('CASAUTH: [2]: validate call: ' .. validate_url) 
            local httpclient = core.httpclient()
            local response = httpclient:get{url=validate_url}
            core.Debug('CASAUTH: [2]: validate status: ' .. tostring(response.status))
            if response.status == 200 then
                -- core.Debug('CASAUTH: [2]: validate response: ' .. tostring(response.body))
                if optVersion == 1 then
                    response = core.tokenize(response.body,'\n')
                    if response[1] == 'yes' then
                        txn.CAS.user = response[2]
                    end
                else
                    response = json.decode(response.body)
                    if response.serviceResponse.authenticationSuccess then
                        txn.CAS.user = response.serviceResponse.authenticationSuccess.user
                        for k,v in pairs(response.serviceResponse.authenticationSuccess.attributes) do
                            txn.CAS.attrs[k] = v[1]
                        end
                    end
                end
            end
        end
    end    
    core.Debug('CASAUTH: result: ' .. json.encode(txn.CAS))
    if optHeaderPrefix then
        txn.http:req_set_header(optHeaderPrefix .. 'version', tostring(txn.CAS.version))
        txn.http:req_set_header(optHeaderPrefix .. 'bypass', tostring(txn.CAS.bypass))
        if txn.CAS.user then
            txn.http:req_set_header(optHeaderPrefix .. 'user', txn.CAS.user)
        end
        for k,v in pairs(txn.CAS.attrs) do
            if type(v) == 'table' then
                v = json.encode(v)
            else
                v = tostring(v)
            end
            txn.http:req_set_header(optHeaderPrefix .. 'attr-' .. k, v)
        end
    end
end

optCasUrlPrefix = nil 
optServiceUrlPrefix = nil
optBypassParameter = 'skipCas' 
optBypassKeep = false
optHeaderPrefix = nil
optRenew = false
optVersion = 3
local args = table.pack(...)
for _,a in ipairs(args) do
    a = core.tokenize(a,'=')
    if a[1] == 'casUrlPrefix' then
        optCasUrlPrefix = a[2]:gsub('/$', '')
    elseif a[1] == 'serviceUrlPrefix' then
        optServiceUrlPrefix = a[2]:gsub('/$', '')
    elseif a[1] == 'bypassParameter' then
        optBypassParameter = a[2]
    elseif a[1] == 'bypassKeep' then
        optBypassKeep = true
    elseif a[1] == 'renew' then 
        optRenew = true
    elseif a[1] == 'headerPrefix' then
        optHeaderPrefix = a[2]
    elseif a[1] == 'version' then
        optVersion = tonumber(a[2])
    end
end
core.Info('CASAUTH: optCasUrlPrefix = ' .. tostring(optCasUrlPrefix))
core.Info('CASAUTH: optServiceUrlPrefix = ' .. tostring(optServiceUrlPrefix))
core.Info('CASAUTH: optBypassParameter = ' .. tostring(optBypassParameter))
core.Info('CASAUTH: optBypassKeep = ' .. tostring(optBypassKeep))
core.Info('CASAUTH: optRenew = ' .. tostring(optRenew))
core.Info('CASAUTH: optHeaderPrefix = ' .. tostring(optHeaderPrefix))
core.Info('CASAUTH: optVersion = ' .. tostring(optVersion))

if optVersion == 1 then
    cas_validate_url = '/validate'
elseif optVersion == 2 then
    cas_validate_url = '/serviceValidate'
else
    cas_validate_url = '/p3/serviceValidate'
end

if optHeaderPrefix then
    optHeaderPrefix = optHeaderPrefix:gsub('%-$', '') .. '-'
end

core.register_action('casauth', { 'http-req' }, action_casauth)
