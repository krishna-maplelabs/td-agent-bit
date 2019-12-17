function filter_log(tag, timestamp, record)
    returnval = -1
    levels = record["log_filters"]
    value = record["level"]
    for filter in levels:gmatch("[^,]+") do
        if filter == value then
            returnval = 0
        end
    end
    return returnval, timestamp, record
end

function addtimeGMToffset_millisecond(tag, timestamp, record)
    now = os.time()
    offset = os.difftime(now, os.time(os.date("!*t", now)))
    record["time"] = math.floor((timestamp-offset)*1000)
    return 1, timestamp, record
end

function addtime_millisecond(tag, timestamp, record)
    record["time"] = math.floor((timestamp)*1000)
    return 1, timestamp, record
end

function nginx_error_transform(tag, timestamp, record)
    returnval = 0
    if record["level"] == "emerg" then
        record["level"] = "error"
        returnval = 1
    end
    return returnval, timestamp, record
end

function access_parsing(tag, timestamp, record)
    if record["path"] == nil or record["path"] == '' then
        returnval = 0
    else
        returnval = 1
        i = 1
        for field in record["path"]:gmatch("[^/]+") do
            key = "path" .. tostring(i)
            record[key] = field
            i = i+1
        end
    end
    return returnval, timestamp, record
end

function access_transform(tag, timestamp, record)
    if record["path"] == nil or record["path"] == '' then
        if record['id2'] == nil or record['id2'] == '' then
            record['path'] = record['path1'] .. "[id]" .. record['path2'] 
        else 
            record['path'] = record['path1'] .. "[id]" .. record['path2'] .. "[id]" .. record['path3']
        end
    end
    return 1, timestamp, record
end

function mysql_error_transform(tag, timestamp, record)
    if record["level"] == nil or record["level"] == '' then
        record["level"] = "info"
        returnval = 1
    end
    record["level"] = string.lower(record["level"])
    return 1, timestamp, record
end

function postgres_general_transform(tag, timestamp, record)
    size,lev = split(record["level"])
    record["level"] = string.lower(lev[1])
    return 1, timestamp, record
end

function apache_error_transform(tag, timestamp, record)
    record["level"] = string.lower(record["level"])
    size,lev = split(record["level"])
    if lev[size] == "warn" then
        record["level"] = "warning"
    end
    return 1, timestamp, record
end

function syslog_transform(tag, timestamp, record)
    if record["level"] == nil or record["level"] == '' then
        record["level"] = "info"
    else
        record["level"] = record["level"]:gsub("%s+", "")
    end
    return 1, timestamp, record
end

function ngoms_transform_noninfo(tag, timestamp, record)
    if record["level"] == nil or record["level"] == '' then
        return 1, timestamp, record
    else
        record["level"] = record["level"]:gsub("%s+", "")
    end
    leveltemp = string.lower(record["level"])
    if leveltemp == "info" then
	return 1, timestamp, record 
    end
    level = record["level"]
    time = record["time"]
    message = record["message"]
    file = record["file"]
    record = {}
    record["time"] = time
    record["message"] = message
    record["file"] = file
    record["level"] = level
    return 1, timestamp, record
end

function syslog_parsing(tag, timestamp, record)
    returnval = -1
    if record["message"] == nil or record["message"] == '' then
        returnval = -1
    else
        returnval = 1
        loglevel = string.match(record["message"], '%[%s*%a+%s*%]')
        if loglevel~= nil then
            record["level"] = string.match(loglevel, '%a+')
        end
    end
    return returnval, timestamp, record
end

function mysql_slowquery_parsing(tag, timestamp, record)
  new_record = record
  message = new_record["message"]
  new_record["sqlquery"] = ""
  i = 1
  for line in message:gmatch("([^\n]*)\n?") do
    if i == 1 then
      new_record["hmstime"] = line
      i = i+1
    else
      if line:match("# ") then
        line = line:gsub("# ","")
        if line:match("User@Host") then
          new_record = extractuserhostid(line,new_record)
        elseif line:match("Schema:") then
          line = line:gsub("Schema:%s*","")
          new_record = extractkeyvalues(line,new_record)
        else
          new_record = extractkeyvalues(line,new_record)
        end
      else
        new_record["sqlquery"] = new_record["sqlquery"].." "..line
      end
    end
  end
  new_record["message"] = nil
  return 1,timestamp,new_record
end

function split(string_to_split)
    local words = {}
    count = 0
    for w in (string_to_split .. ":"):gmatch("([^:]*):") do 
        table.insert(words, w)
        count = count + 1 
    end
    return count,words
end

function extractuserhostid(line,record)
    new_record = record
    fields = {}
    index = 1
    for field in line:gmatch("[^%s]+") do
        fields[index] = field
        index = index + 1
    end
    new_record["user"] = fields[2]
    new_record["host"] = fields[4]
    new_record["host_ip"] = fields[5]
    if fields[6] ~= nil and fields[6] == "Id:" then 
        new_record["Id"] = fields[7]
     end
    return new_record
end

function extractkeyvalues(line,record)
    new_record = record
    key = ""
    for field in line:gmatch("[^%s]+") do
        if key == "" then key = field:gsub(":","")
        else 
            new_record[key] = tonumber(field)
            if new_record[key] == nil then new_record[key] = field end
            key = ""
        end
    end
    return new_record
end

function defaultdiscovery(tag,timestamp,record)
    if record["level"] == nil or record["level"] == '' then
	return 0, timestamp, record 
    else
        record["level"] = record["level"]:gsub("%s+", "")
    end
    leveltemp = string.lower(record["level"])
    if leveltemp ~= "info" then
      level = record["level"]
      time = record["time"]
      message = record["message"]
      file = record["file"]
      logrecord = {}
      logrecord["time"] = time
      logrecord["message"] = message
      logrecord["file"] = file
      logrecord["level"] = level
      return 1, timestamp, logrecord 
    end
    logrecord = record
    message = logrecord["message"]
    numberfields = logrecord["numberfields"]
    stringfields = logrecord["stringfields"]
    if numberfields == nil then numberfields = "" end
    if stringfields == nil then stringfields = "" end
  
    for key,value in string.gmatch(message, "(%w+)%s*=%s*([^%s,%]%[%)%(]+)") do
      if searchfield(key,stringfields) then
	logrecord[key] = value
      else
        logrecord[key] = tonumber(value)
        if logrecord[key] == nil then
          if not searchfield(key,numberfields) then
            logrecord[key] = value
          end
        end
      end
    end
    return 1, timestamp, logrecord
end

function defaultextraction(tag,timestamp,record)
  logrecord = record

  numberfields = logrecord["numberfields"]
  if numberfields == nil then numberfields = "" end
  for key,value in pairs(record) do
    if searchfield(key,numberfields) then
      logrecord[key] = tonumber(value)
    else
      logrecord[key] = value
    end
  end
  logrecord["numberfields"] = nil
  logrecord["stringfields"] = nil
  return 1, timestamp, logrecord
end

function searchfield(field,fields)
  found = false
  for item in fields:gmatch("[^,]+") do
    if item == field then
      found = true
      break
    end
  end
  return found
end
