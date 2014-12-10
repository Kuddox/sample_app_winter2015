require 'test_helper'

class UsersHelperTest < ActionView::TestCase

  def setup
    @user = User.new(name: 'Carlos', email: 'carlos@devpointlabs.com')
  end

  test "gravatar_for takes an option for size" do
    actual_link = '<img alt="Carlos" class="gravatar" src="https://s.gravatar.com/avatar/aa2fe02a6a7517afe1a370d76f21e3d8?s=80" />' 
    
    assert_equal gravatar_for(@user), actual_link
    assert_includes gravatar_for(@user, size: 300), '?s=300'
  end

end
