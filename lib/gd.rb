require 'active_support/core_ext/hash'
require 'gooddata'
require 'pp'
require 'logger'
require 'rainbow'
require 'highline/import'

module Gd
  module Commands

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
          :role         => as['content']['userRoles'].first
        }
      end
    end

    def self.get_domain_users(domain)
      result = GoodData.get("/gdc/account/domains/#{domain}/users")

      result['accountSettings']['items'].map do |u|
        as = u['accountSetting']
        {
          :login        => as['login'],
          :uri          => as['links']['self'],
          :first_name   => as['firstName'],
          :last_name    => as['lastName']
        }
      end
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


    def self.create_user(users_data, domain, pid, roles)
      users_data.symbolize_keys!
      
      
      account_setting = {
        :accountSetting => {
          :login              => users_data[:login],
          :password           => users_data[:password],
          :verifyPassword     => users_data[:password],
          :firstName          => users_data[:first_name],
          :lastName           => users_data[:last_name],
          :ssoProvider        => users_data[:sso_provider]
        }
      }
      
      # pp account_setting
      # pp "/gdc/account/domains/#{domain}/users"
      begin
        result = GoodData.post("/gdc/account/domains/#{domain}/users", account_setting)
      rescue RestClient::BadRequest => e
        STDERR.puts "User #{users_data[:login]} could not be created."
        return
      end
        user_uri = result["uri"]
        invitation = {
          :user => {
            :content => {
              :status => 'ENABLED'
            },
            :links => {
              :self => user_uri
            }
          }
        }
        result = GoodData.post("/gdc/projects/#{pid}/users", invitation)
      pp roles
        if users_data.has_key? "role"
          role = roles[users_data["role"]]
        pp role
          role_structure = {
            :associateUser => {
              :user => user_uri
            }
          }
          GoodData.post(role[:user_uri], role_structure)
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
      GoodData.post(role_uri, role_structure)
    end

  end
end
