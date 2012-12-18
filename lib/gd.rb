require 'active_support/core_ext/hash'
require 'gooddata'
require 'pp'
require 'logger'
require 'rainbow'
require 'highline/import'
require 'salesforce'

module Gd
  module Commands

    NONE = "None"

    CONFIG_TEMPLATE = {
      :projects => [],
      :users => []
    }

    def self.load_config
      home = `echo $HOME`.chomp
      path = "#{home}/.gd"
      # pp CONFIG_TEMPLATE
      File.open(path, 'w') {|f| f.write(JSON.pretty_generate(CONFIG_TEMPLATE))} unless File.exists?(path)
      JSON.parse(File.read(path))
    end

    def self.save_config(config)
      home = `echo $HOME`.chomp
      File.open("#{home}/.gd", 'w') {|f| f.write(JSON.pretty_generate(config)) }
    end

    def self.clone_project(pid, options={})
      with_data   = options[:with_data]
      with_users  = options[:with_users]
      
      export = {
        :exportProject => {
          :exportUsers => with_users ? 1 : 0,
          :exportData => with_data ? 1 : 0
        }
      }
      
      result = GoodData.post("/gdc/md/#{pid}/maintenance/export", export)
      token = result["exportArtifact"]["token"]
      status_url = result["exportArtifact"]["status"]["uri"]
      
      state = GoodData.get(status_url)["taskState"]["status"]
      while state == "RUNNING"
        sleep 5
        result = GoodData.get(status_url) 
        state = result["taskState"]["status"]
      end
      
      old_project = GoodData::Project[pid]
      project_uri = self.create_project("Clone of #{old_project.title}")
      new_project = GoodData::Project[project_uri]
      
      import = {
        :importProject => {
          :token => token
        }
      }
      
      result = GoodData.post("/gdc/md/#{new_project.obj_id}/maintenance/import", import)
      status_url = result["uri"]
      state = GoodData.get(status_url)["taskState"]["status"]
      while state == "RUNNING"
        sleep 5
        result = GoodData.get(status_url) 
        state = result["taskState"]["status"]
      end
    end

    def self.create_project(title, description="")
      project = {
        :project => {
          :content =>{
            :guidedNavigation => 1
          },
          :meta => {
            :title => title,
            :summary => description,
            :projectTemplate => "/projectTemplates/empty/1"
          }
        }
      }
      
      result = GoodData.post("/gdc/projects", project)
      result["uri"]
    end

    def self.validate_project(pid)

      result = GoodData.post("/gdc/md/#{pid}/validate", {
        "validateProject" => [ 'LDM', 'PDM', 'IO']
      })
      status = GoodData.get(result["uri"])["validateResult"]["state"]
      while status != "FINISHED"
        sleep 5
        validation_result = GoodData.get(result["uri"])
        status = validation_result["validateResult"]["state"]
      end

      result = validation_result["validateResult"]["status"] == "OK"
      [result, validation_result]
    end

    def self.get_users(pid)
      result = GoodData.get("/gdc/projects/#{pid}/users")
      result["users"].map do |u|
        as = u['user']
        {
          :login        => as['content']['email'],
          :uri          => as['links']['self'],
          :first_name   => as['content']['firstname'],
          :last_name    => as['content']['lastname'],
          :role         => as['content']['userRoles'].first,
          :status       => as['content']['status']
        }
      end
    end

    def self.get_domain_users(domain)
      next_uri = "/gdc/account/domains/#{domain}/users"
      
      users = []
      while next_uri do
        result = GoodData.get(next_uri)
        result['accountSettings']['items'].each do |u|
          as = u['accountSetting']
          users << {
            :login        => as['login'],
            :uri          => as['links']['self'],
            :first_name   => as['firstName'],
            :last_name    => as['lastName']
          }
        end
        
        next_uri = result['accountSettings']['paging']['next']
      end
      users
    end

    def self.get_roles(pid)
      roles_response = GoodData.get("/gdc/projects/#{pid}/roles")
      
      roles = {}
      roles_response["projectRoles"]["roles"].each do |role_uri|
        r = GoodData.get(role_uri)
        identifier = r["projectRole"]["meta"]["identifier"]
        roles[identifier] = {
          :user_uri => r["projectRole"]["links"]["roleUsers"],
          :uri      => role_uri
        }
      end
      roles
    end

    def self.set_user_status(user_uri, pid, status, options = {})
      fail "Status needs to be ENABLED or DISABLED" if status != "ENABLED" && status != "DISABLED"
      invitation = {
        :user => {
          :content => {
            :status => status
          },
          :links => {
            :self => user_uri
          }
        }
      }
      # Adding user role when inviting user to project
      invitation[:user][:content].merge!(options)
      GoodData.connection.retryable(:tries => 3, :on => RestClient::ServiceUnavailable) do
        GoodData.post("/gdc/projects/#{pid}/users", invitation)
      end
    end

    def self.compute_report(id)
      report = GoodData::Report[id]
      report.execute
    end

    def self.create_users_from_csv(filename, pid, domain)
      result = []
      domain_users = {}
      Gd::Commands.get_domain_users(domain).each do |u|
        domain_users[u[:login]] = u
      end
      
      FasterCSV.foreach(filename, :headers => true, :return_headers => false) do |row|
        hash_row = row.to_hash
        result << create_user(hash_row, domain, pid) unless domain_users.has_key?(hash_row["login"])
      end
      result
    end

    def self.create_users_from_sf(login, password, pid, domain)
      sf_users = grab_users_from_sf(login, password, pid)
      domain_users = {}
      Gd::Commands.get_domain_users(domain).each do |u|
        domain_users[u[:login]] = u
      end
      
      sf_users.reject {|user| domain_users.has_key?(user[:login])}.map {|user| create_user(user, domain, pid)}
    end

    def self.create_user(users_data, domain, pid, roles=nil)
      users_data.symbolize_keys!

      password = users_data[:password] ? users_data[:password] : rand(10000000000000).to_s

      account_setting = {
        :accountSetting => {
          :login              => users_data[:login],
          :password           => password,
          :verifyPassword     => password,
          :firstName          => users_data[:first_name],
          :lastName           => users_data[:last_name],
          :ssoProvider        => users_data[:sso_provider] || nil
        }
      }
      
      begin
        GoodData.post("/gdc/account/domains/#{domain}/users", account_setting)
        return [users_data[:login], "ok"]
      rescue RestClient::BadRequest => e
        STDERR.puts "User #{users_data[:login]} could not be created."
        return
      rescue RestClient::InternalServerError => e
        STDERR.puts "User #{users_data[:login]} could not be created and returned 500."
        return
      end
    end

    def self.delete_user(uri)
      GoodData.delete(uri)
    end

    def self.set_role(role_uri, user_uri)
      role_structure = {
        :associateUser => {
          :user => user_uri
        }
      }
      GoodData.connection.retryable(:tries => 3, :on => RestClient::ServiceUnavailable) do
        GoodData.post(role_uri, role_structure)
      end
    end


    def self.roles_are_different(sf_user, gd_user)
      fail "Wrong SF role" if sf_user[:role].nil? || sf_user[:role] == ""
      return true if gd_user.nil?
      sf_user[:role] != gd_user[:role]
    end

    def self.grab_users_from_sf(sf_login, sf_password, pid, options={})

      project_specific_sf_field = options[:project_specific_sf_field] || "Role_In_GD__c"
      project_agnostic_sf_field = options[:project_agnostic_sf_field] || "Role_In_GD_#{pid}__c"
      begin
        client = Salesforce::Client.new(sf_login, sf_password)
      rescue RuntimeError => e
        puts e.message
        exit 1
      end
      # Verify SF Setup
      # See https://confluence.gooddata.com/confluence/display/PS/Sales+force+user+synchronization for explanation
      user_fields = client.fields('User')
      project_specific = user_fields.include?(project_specific_sf_field) && project_specific_sf_field
      project_agnostic = user_fields.include?(project_agnostic_sf_field) && project_agnostic_sf_field
      field = project_specific || project_agnostic

      if !project_agnostic && !project_specific then
        puts "SF setup does not seem to be right. There is neither #{project_specific_sf_field} nor #{project_agnostic_sf_field} field in SF. Plese see https://confluence.gooddata.com/confluence/display/PS/Sales+force+user+synchronization for explanation"
        exit 1
      end

      # puts "Grabbing data from SF"
      data = []
      client.grab :module => "User", :output => data, :as_hash => true, :fields => "FirstName, LastName, Email, #{field}"
      
      data.map do |line|
        {
          :first_name     => line[:FirstName],
          :last_name      => line[:LastName],
          :login          => line[:Email],
          :sso_provider   => "SALESFORCE",
          :role           => line[field.to_sym],
          :login          => line[:Email]
        }
      end

    end

    def self.sync_users_in_project_from_sf(sf_login, sf_password, pid, domain, options={})
      sf_users = grab_users_from_sf(sf_login, sf_password, pid, options)
      sf_users_hash = {}
      sf_users.each do |user|
        sf_users_hash[user[:login]] = user if !user[:role].nil? && user[:role] != NONE
      end
      sync_users_in_project(sf_users_hash, pid, domain, options)
    end

    
    def self.sync_users_in_project_from_csv_and_snapshot_file(file_name,gooddata_snapshot_file, pid, domain, options={})
       
      
      csv_users = {}
      FasterCSV.foreach(file_name, :headers => true, :return_headers => false) do |line|
        if (!line.headers.include?('role') || (!line['role'].nil? && line['role'] != NONE ))
          csv_users[line['login']] = {
            :first_name     => line['first_name'],
            :last_name      => line['last_name'],
            :login          => line['login'],
            :sso_provider   => line['sso_provider'],
            :role            => line['role']
          }
        end
      end
     
      
      gooddata_users = {}
      FasterCSV.foreach(gooddata_snapshot_file, :headers => false, :return_headers => false) do |line|
          gooddata_users[line[0]] = {
            :login         => line[0],
            :role          => line[1],
            :uri           => line[2],
            :status        => line[3]
          }
      end

      sync_users_in_project_gooddata_snapshot(csv_users,gooddata_users, pid, domain, options)

    end

    
    
    
    def self.sync_users_in_project_from_csv(file_name, pid, domain, options={})
      csv_users = {}
      FasterCSV.foreach(file_name, :headers => true, :return_headers => false) do |line|
        if (!line.headers.include?('role') || (!line['role'].nil? && line['role'] != NONE ))
          csv_users[line['login']] = {
            :first_name     => line['first_name'],
            :last_name      => line['last_name'],
            :login          => line['login'],
            :sso_provider   => line['sso_provider'],
            :role            => line['role']
          }
        end
      end
      sync_users_in_project(csv_users, pid, domain, options)

    end

    def self.sync_users_in_project(users_to_sync, pid, domain, options)
      black_list = options[:black_list] || []
      
      roles = roles = Gd::Commands.get_roles(pid)
      project_users = {}

      # puts "Grabbing project users from GD"
      # transform users to a way that it can be searched fast + adding some additional info
      Gd::Commands.get_users(pid).each do |u|
        project_users[u[:login]] = u
        role_name = nil
        roles.find {|k,v| role_name = k if v[:uri] == u[:role]}
        u[:role] = role_name
      end

      domain_users = {}
      
      Gd::Commands.get_domain_users(domain).each do |u|
        blacklisted = black_list.any? { |black_list_item| u[:login].match(Regexp.new(Regexp.quote(black_list_item))) }
        domain_users[u[:login]] = u unless blacklisted
      end

      users_to_invite = []
      users_to_uninvite = []
      users_to_change_role = []
      users_to_sync.keys.each do |login|
        user = users_to_sync[login]
        # If there is a user in input file that is in project and has different roles, chage the role
        users_to_change_role  << login if project_users.has_key?(login) && roles_are_different(user, project_users[login])
        # If there is a user in input that is not in project or he is disabled in the project enable him
        users_to_invite       << [login,user[:role]] if !project_users.has_key?(login) || project_users[login][:status] == "DISABLED"
      end

     
      
      project_users.keys.each do |login|
        project_user = project_users[login]
        # if there is a user in the project which are not in the input data && this user does not match black list and is enabled => remove him
        blacklisted = black_list.any? { |black_list_item| login.match(Regexp.new(Regexp.quote(black_list_item))) }
        users_to_uninvite << login if !users_to_sync.has_key?(login) && !blacklisted && project_user[:status] == "ENABLED"
      end

      # EXECUTE
      if users_to_invite.count > 0
        puts "Inviting users"
        users_to_invite.each do |value|
          # Value contains name of the role from file
          role_uri = ""
          roles.find {|k,v| role_uri = v[:uri] if k == value[1]}
          user = domain_users[value[0]]
          if user.nil?
            puts "Cannot add user #{value[0]}, user not in domain and probably cannot be created"
            next
          end
          Gd::Commands.set_user_status(user[:uri], pid, "ENABLED",{:userRoles => [role_uri]})
          puts "#{user[:login]}"
        end
      end
      # refresh users in project
      project_users = {}

      # Refresh users in project so we have the latest info
      # puts "Grabbing project users from GD"
      Gd::Commands.get_users(pid).each do |u|
        project_users[u[:login]] = u
        role_name = nil
        roles.find {|k,v| role_name = k if v[:uri] == u[:role]}
        u[:role] = role_name
      end

      if users_to_change_role.count > 0
        puts "Changing roles"
        users_to_change_role.each do |login|
          user = project_users[login]
          if user.nil?
            puts "Role for User #{login} cannot be changed it is not in the project"
            next
          end
          role_uri = roles[users_to_sync[login][:role]]
          new_role_name = users_to_sync[login][:role]
          if role_uri.nil?
            puts "#{login} - Role could not be changed to #{new_role_name}"
          else
            puts "#{login} - from #{user[:role]} to #{new_role_name}"
            Gd::Commands.set_role(role_uri[:user_uri], user[:uri])
          end
        end
      end

      if users_to_uninvite.count > 0
        puts "Disabling users"
        users_to_uninvite.each do |login|
          user = project_users[login]
          Gd::Commands.set_user_status(user[:uri], pid, "DISABLED")
          puts "#{user[:login]}"
        end
      end
    end

    
    def self.sync_users_in_project_gooddata_snapshot(users_to_sync,gooddata_users, pid, domain, options)
      black_list = options[:black_list] || []
      
      roles = roles = Gd::Commands.get_roles(pid)
      
      project_users = {}

      gooddata_users.each do |k,gd_user|
        # Role is already set in this one
        role_name = nil
        roles.find {|k,v| role_name = k if v[:uri] == gd_user[:role]}
        gd_user[:role] = role_name 
        project_users[gd_user[:login]] = gd_user
      end

      domain_users = {}
      
      Gd::Commands.get_domain_users(domain).each do |u|
        blacklisted = black_list.any? { |black_list_item| u[:login].match(Regexp.new(Regexp.quote(black_list_item))) }
        domain_users[u[:login]] = u unless blacklisted
      end

      users_to_invite = []
      users_to_uninvite = []
      users_to_change_role = []
      users_to_sync.keys.each do |login|
        user = users_to_sync[login]
        # If there is a user in input file that is in project and has different roles, chage the role
        users_to_change_role  << login if project_users.has_key?(login) && roles_are_different(user, project_users[login])
        # If there is a user in input that is not in project or he is disabled in the project enable him
        users_to_invite       << [login,user[:role]] if !project_users.has_key?(login) || project_users[login][:status] == "DISABLED"
      end

     
      
      project_users.keys.each do |login|
        project_user = project_users[login]
        # if there is a user in the project which are not in the input data && this user does not match black list and is enabled => remove him
        blacklisted = black_list.any? { |black_list_item| login.match(Regexp.new(Regexp.quote(black_list_item))) }
        users_to_uninvite << login if !users_to_sync.has_key?(login) && !blacklisted && project_user[:status] == "ENABLED"
      end

#       puts users_to_change_role.count      
#       puts users_to_invite.count
#       puts users_to_uninvite.count
      

      #EXECUTE
      if users_to_invite.count > 0
        puts "Inviting users"
        users_to_invite.each do |value|
          # Value contains name of the role from file
          role_uri = ""
          roles.find {|k,v| role_uri = v[:uri] if k == value[1]}
          user = domain_users[value[0]]
          if user.nil?
            puts "Cannot add user #{value[0]}, user not in domain and probably cannot be created"
            next
          end
          Gd::Commands.set_user_status(user[:uri], pid, "ENABLED",{:userRoles => [role_uri]})
          puts "#{user[:login]}"
        end
      end
      
      # WE cannot get new status so ignoring
      
      # refresh users in project
      # project_users = {}

      # Refresh users in project so we have the latest info
      # puts "Grabbing project users from GD"
#       Gd::Commands.get_users(pid).each do |u|
#         project_users[u[:login]] = u
#         role_name = nil
#         roles.find {|k,v| role_name = k if v[:uri] == u[:role]}
#         u[:role] = role_name
#       end

      
      if users_to_change_role.count > 0
        puts "Changing roles"
        users_to_change_role.each do |login|
          user = project_users[login]
          if user.nil?
            puts "Role for User #{login} cannot be changed it is not in the project"
            next
          end
          role_uri = roles[users_to_sync[login][:role]]
          new_role_name = users_to_sync[login][:role]
          if role_uri.nil? || role_uri == ""
            puts "#{login} - Role could not be changed to #{new_role_name}"
          else
            puts "#{login} - from #{user[:role]} to #{new_role_name}"
            Gd::Commands.set_role(role_uri[:user_uri], user[:uri])
          end
        end
      end

      if users_to_uninvite.count > 0
        puts "Disabling users"
        users_to_uninvite.each do |login|
          user = project_users[login]
          Gd::Commands.set_user_status(user[:uri], pid, "DISABLED")
          puts "#{user[:login]}"
        end
      end
    end

    
    
    
    def self.delete_all_mufs(pid)
      mufs = GoodData.get("/gdc/md/#{pid}/query/userfilters")["query"]["entries"]
      mufs.each do |muf|
        GoodData.delete(muf["link"])
      end
    end
    
  end
end
