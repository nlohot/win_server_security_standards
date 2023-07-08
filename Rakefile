# frozen_string_literal: true

$stdout.sync = true

task default: [:static_analysis, :integration]

desc 'Run Tests - Unit & Rubocop'
task static_analysis: [:cop, :unit]

# Define rubocop
desc 'Ruby code style check - Rubocop'
task :cop do
  puts 'rubocop '.upcase * 5
  sh 'rubocop --cache false -c .rubocop.yml --format simple --format html -o reports/rubocop.html ./'
end

desc 'Ruby code style check - Rubocop'
task :autocop do
  puts 'rubocop '.upcase * 5
  sh 'rubocop --cache false -a .rubocop.yml --format simple --format html -o reports/rubocop.html ./'
end

desc 'unit test - ChefSpec'
task :unit do
  puts 'ChefSpec '.upcase * 5
  sh 'chef exec rspec'
end

desc 'Integration test- Test-Kitchen'
task :integration do
  puts 'test-kitchen '.upcase * 5
  begin
    sh 'kitchen test'
  rescue StandardError
    sh 'kitchen destroy'
  end
end

directory 'reports'
