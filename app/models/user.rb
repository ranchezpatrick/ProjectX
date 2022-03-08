class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable

  def admin?
    role == "Admin"
  end

  def super_admin?
    role == "super_admin"
  end

  def member?
    role == "member"
  end
end
