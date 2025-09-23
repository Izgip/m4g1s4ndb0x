-- sandboxos.lua
-- Advanced Sandboxing System for CC:Tweaked

local sandboxos = {}

-- Configuration
sandboxos.config = {
    MAX_PROGRAM_TIME = 30, -- seconds
    ALLOWED_FS_PATTERNS = {
        "^/rom/",
        "^/sandbox/",
        "^/tmp/"
    },
    BLOCKED_APIS = {
        "os.shutdown", "os.reboot", "fs.delete", "fs.move",
        "fs.copy", "http.request", "commands.exec"
    }
}

-- Sandbox levels
sandboxos.LEVELS = {
    NONE = 0,      -- No restrictions (admin mode)
    LOW = 1,       -- Basic restrictions
    MEDIUM = 2,    -- Moderate restrictions
    HIGH = 3,      -- Strict restrictions
    MAXIMUM = 4    -- Maximum isolation
}

-- Runtime environment tracking
sandboxos.runtime = {
    active_sandboxes = {},
    sandbox_id_counter = 0
}

-- Security policies for each level
sandboxos.policies = {
    [sandboxos.LEVELS.NONE] = {
        name = "NONE",
        description = "No restrictions - full system access",
        file_access = "full",
        api_restrictions = {},
        time_limit = nil,
        network_access = true,
        peripheral_access = true
    },
    [sandboxos.LEVELS.LOW] = {
        name = "LOW",
        description = "Basic restrictions - prevent system damage",
        file_access = "readonly_system",
        api_restrictions = {"os.shutdown", "os.reboot", "fs.delete"},
        time_limit = 60,
        network_access = true,
        peripheral_access = true
    },
    [sandboxos.LEVELS.MEDIUM] = {
        name = "MEDIUM",
        description = "Moderate restrictions - limited file access",
        file_access = "sandbox_only",
        api_restrictions = {
            "os.shutdown", "os.reboot", "fs.delete", "fs.move", "fs.copy",
            "commands.exec", "http.request"
        },
        time_limit = 30,
        network_access = false,
        peripheral_access = false
    },
    [sandboxos.LEVELS.HIGH] = {
        name = "HIGH",
        description = "Strict restrictions - isolated environment",
        file_access = "virtual_fs",
        api_restrictions = "most",
        time_limit = 15,
        network_access = false,
        peripheral_access = false,
        memory_limit = 10000
    },
    [sandboxos.LEVELS.MAXIMUM] = {
        name = "MAXIMUM",
        description = "Maximum isolation - minimal API access",
        file_access = "none",
        api_restrictions = "all_non_essential",
        time_limit = 10,
        network_access = false,
        peripheral_access = false,
        memory_limit = 5000
    }
}

-- Create a secure sandbox environment
function sandboxos.createEnvironment(level, custom_policy)
    local policy = custom_policy or sandboxos.policies[level]
    if not policy then
        error("Invalid sandbox level: " .. tostring(level))
    end
    
    local env = {
        policy = policy,
        start_time = os.epoch("utc"),
        file_operations = 0,
        api_calls = {},
        violations = {}
    }
    
    -- Set up the environment based on policy
    env = sandboxos.setupFilesystem(env, policy)
    env = sandboxos.setupAPI(env, policy)
    env = sandboxos.setupLimits(env, policy)
    
    return env
end

-- Set up filesystem restrictions
function sandboxos.setupFilesystem(env, policy)
    local fs_restrictions = {}
    
    if policy.file_access == "full" then
        -- No restrictions
        fs_restrictions.canRead = function(path) return true end
        fs_restrictions.canWrite = function(path) return true end
        fs_restrictions.canList = function(path) return true end
        
    elseif policy.file_access == "readonly_system" then
        -- Read-only system files
        fs_restrictions.canRead = function(path)
            return sandboxos.isAllowedPath(path)
        end
        fs_restrictions.canWrite = function(path)
            return path:match("^/sandbox/") or path:match("^/tmp/")
        end
        fs_restrictions.canList = function(path)
            return sandboxos.isAllowedPath(path)
        end
        
    elseif policy.file_access == "sandbox_only" then
        -- Only sandbox directory access
        fs_restrictions.canRead = function(path)
            return path:match("^/sandbox/") or path:match("^/rom/")
        end
        fs_restrictions.canWrite = function(path)
            return path:match("^/sandbox/")
        end
        fs_restrictions.canList = function(path)
            return path:match("^/sandbox/") or path:match("^/rom/")
        end
        
    elseif policy.file_access == "virtual_fs" then
        -- Virtual filesystem (in-memory only)
        env.virtual_fs = {}
        fs_restrictions.canRead = function(path)
            return env.virtual_fs[path] ~= nil
        end
        fs_restrictions.canWrite = function(path)
            return path:match("^/virtual/")
        end
        fs_restrictions.canList = function(path)
            return path == "/virtual"
        end
        
    elseif policy.file_access == "none" then
        -- No filesystem access
        fs_restrictions.canRead = function(path) return false end
        fs_restrictions.canWrite = function(path) return false end
        fs_restrictions.canList = function(path) return false end
    end
    
    env.fs_restrictions = fs_restrictions
    return env
end

-- Set up API restrictions
function sandboxos.setupAPI(env, policy)
    local api_restrictions = {}
    local blocked_apis = {}
    
    -- Convert policy restrictions to blocked API list
    if type(policy.api_restrictions) == "table" then
        for _, api in ipairs(policy.api_restrictions) do
            blocked_apis[api] = true
        end
    elseif policy.api_restrictions == "most" then
        blocked_apis = {
            ["os."] = true, ["fs."] = true, ["http."] = true,
            ["commands."] = true, ["peripheral."] = true
        }
    elseif policy.api_restrictions == "all_non_essential" then
        blocked_apis = {
            ["os."] = true, ["fs."] = true, ["http."] = true,
            ["commands."] = true, ["peripheral."] = true,
            ["io."] = true, ["term."] = true, ["window."] = true
        }
    end
    
    api_restrictions.isAllowed = function(api_name)
        for blocked_pattern, _ in pairs(blocked_apis) do
            if api_name:match(blocked_pattern) then
                return false
            end
        end
        return true
    end
    
    env.api_restrictions = api_restrictions
    return env
end

-- Set up resource limits
function sandboxos.setupLimits(env, policy)
    env.limits = {
        time_limit = policy.time_limit,
        memory_limit = policy.memory_limit,
        max_file_ops = policy.max_file_ops or 1000,
        max_api_calls = policy.max_api_calls or 10000
    }
    return env
end

-- Check if path is allowed
function sandboxos.isAllowedPath(path)
    for _, pattern in ipairs(sandboxos.config.ALLOWED_FS_PATTERNS) do
        if path:match(pattern) then
            return true
        end
    end
    return false
end

-- Monitor program execution
function sandboxos.monitorExecution(env, program_path, ...)
    local start_time = os.epoch("utc")
    local result = {success = false, output = "", violations = {}}
    
    -- Create secure environment
    local secure_env = setmetatable({}, {
        __index = function(t, k)
            -- Check API restrictions
            if not env.api_restrictions.isAllowed(k) then
                table.insert(result.violations, "Blocked API access: " .. k)
                return nil
            end
            return _G[k]
        end
    })
    
    -- Override filesystem functions
    secure_env.fs = {}
    for name, func in pairs(fs) do
        if name:match("^list$") or name:match("^exists$") or name:match("^isDir$") then
            secure_env.fs[name] = function(path)
                if not env.fs_restrictions.canList(path) then
                    table.insert(result.violations, "Filesystem list violation: " .. path)
                    return nil
                end
                env.file_operations = env.file_operations + 1
                return func(path)
            end
        elseif name:match("^open$") or name:match("^read$") then
            secure_env.fs[name] = function(path, ...)
                if not env.fs_restrictions.canRead(path) then
                    table.insert(result.violations, "Filesystem read violation: " .. path)
                    return nil
                end
                env.file_operations = env.file_operations + 1
                return func(path, ...)
            end
        elseif name:match("^write$") or name:match("^delete$") or name:match("^makeDir$") then
            secure_env.fs[name] = function(path, ...)
                if not env.fs_restrictions.canWrite(path) then
                    table.insert(result.violations, "Filesystem write violation: " .. path)
                    return nil
                end
                env.file_operations = env.file_operations + 1
                return func(path, ...)
            end
        else
            secure_env.fs[name] = func
        end
    end
    
    -- Set up timeout monitoring
    local function checkTimeout()
        local current_time = os.epoch("utc")
        if env.limits.time_limit and 
           (current_time - start_time) > (env.limits.time_limit * 1000) then
            error("SANDBOX_TIMEOUT")
        end
    end
    
    -- Execute program in protected environment
    local ok, program_result = xpcall(function()
        local program_args = {...}
        -- Load the program
        if not fs.exists(program_path) then
            error("Program not found: " .. program_path)
        end
        
        local program = fs.open(program_path, "r")
        local code = program.readAll()
        program.close()
        
        -- Create sandboxed function
        local chunk, err = load(code, program_path, "t", secure_env)
        if not chunk then
            error("Failed to load program: " .. err)
        end
        
        -- Execute with timeout checking
        local args = program_args
        local co = coroutine.create(function()
            return chunk(table.unpack(args))
        end)
        
        while coroutine.status(co) ~= "dead" do
            checkTimeout()
            local co_ok, co_result = coroutine.resume(co)
            if not co_ok then
                error(co_result)
            end
            os.sleep(0) -- Yield to allow timeout checking
        end
        
        return true
    end, function(err)
        return err
    end)
    
    result.success = ok
    if not ok then
        result.output = program_result
        if program_result == "SANDBOX_TIMEOUT" then
            table.insert(result.violations, "Execution time limit exceeded")
        end
    end
    
    result.execution_time = (os.epoch("utc") - start_time) / 1000
    result.file_operations = env.file_operations
    
    return result
end

-- Main function to run programs with sandboxing
function sandboxos.run(program_path, level, ...)
    local args = {...}
    if not program_path then
        error("Program path required")
    end
    
    level = level or sandboxos.LEVELS.MEDIUM
    
    print("SandBoxOS: Starting program in sandbox level " .. 
          sandboxos.policies[level].name)
    print("Program: " .. program_path)
    print("Security: " .. sandboxos.policies[level].description)
    
    -- Create sandbox environment
    local env = sandboxos.createEnvironment(level)
    
    -- Run the program
    local result = sandboxos.monitorExecution(env, program_path, ...)
    
    -- Report results
    print("\n--- SandBoxOS Execution Report ---")
    print("Program: " .. program_path)
    print("Sandbox Level: " .. sandboxos.policies[level].name)
    print("Status: " .. (result.success and "COMPLETED" or "FAILED"))
    print("Execution Time: " .. string.format("%.2f", result.execution_time) .. "s")
    print("File Operations: " .. result.file_operations)
    
    if #result.violations > 0 then
        print("Security Violations: " .. #result.violations)
        for i, violation in ipairs(result.violations) do
            print("  " .. i .. ". " .. violation)
        end
    end
    
    if not result.success then
        print("Error: " .. result.output)
    end
    
    print("---------------------------------")
    
    return result
end

-- Command line interface
if arg and arg[0] and arg[0]:match("sandboxos") then
    local args = {...}
    
    if #args == 0 then
        print("SandBoxOS - Advanced Sandboxing System")
        print("Usage: sandboxos <level> <program> [args...]")
        print("Levels: 0=NONE, 1=LOW, 2=MEDIUM, 3=HIGH, 4=MAXIMUM")
        print("Example: sandboxos 2 /rom/programs/fun/advanced/paint")
        return
    end
    
    local level = tonumber(args[1])
    local program_path = args[2]
    
    if not level or level < 0 or level > 4 then
        print("Error: Invalid sandbox level. Use 0-4.")
        return
    end
    
    if not program_path then
        print("Error: Program path required.")
        return
    end
    
    local program_args = {}
    for i = 3, #args do
        table.insert(program_args, args[i])
    end
    
    sandboxos.run(program_path, level, table.unpack(program_args))
end

return sandboxos
