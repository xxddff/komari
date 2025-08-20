package accounts

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/utils"

	"github.com/google/uuid"
)

const constantSalt = "06Wm4Jv1Hkxx"

// CheckPassword 检查密码是否正确
//
// 如果密码正确，返回用户的 UUID 和 true；否则返回空字符串和 false
func CheckPassword(username, passwd string) (uuid string, success bool) {
	db := dbcore.GetDBInstance()
	var user models.User
	result := db.Where("username = ?", username).First(&user)
	if result.Error != nil {
		// 静默处理错误，不显示日志
		return "", false
	}
	if hashPasswd(passwd) != user.Passwd {
		return "", false
	}
	return user.UUID, true
}

// ForceResetPassword 强制重置用户密码
func ForceResetPassword(username, passwd string) (err error) {
	db := dbcore.GetDBInstance()
	result := db.Model(&models.User{}).Where("username = ?", username).Update("passwd", hashPasswd(passwd))
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("无法找到用户名")
	}
	return nil
}

// hashPasswd 对密码进行加盐哈希
func hashPasswd(passwd string) string {
	saltedPassword := passwd + constantSalt
	hash := sha256.New()
	hash.Write([]byte(saltedPassword))
	hashedPassword := base64.StdEncoding.EncodeToString(hash.Sum(nil))
	return hashedPassword
}

func CreateAccount(username, passwd string) (user models.User, err error) {
	db := dbcore.GetDBInstance()
	hashedPassword := hashPasswd(passwd)
	user = models.User{
		UUID:     uuid.New().String(),
		Username: username,
		Passwd:   hashedPassword,
	}
	err = db.Create(&user).Error
	if err != nil {
		return models.User{}, err
	}
	return user, nil
}

func DeleteAccountByUsername(username string) (err error) {
	db := dbcore.GetDBInstance()
	err = db.Where("username = ?", username).Delete(&models.User{}).Error
	if err != nil {
		return err
	}
	return nil
}

// 创建默认管理员账户，使用环境变量 ADMIN_USERNAME 作为用户名，环境变量 ADMIN_PASSWORD 作为密码
func CreateDefaultAdminAccount() (username, passwd string, err error) {
	db := dbcore.GetDBInstance()

	username = os.Getenv("ADMIN_USERNAME")
	if username == "" {
		username = "admin"
	}

	passwd = os.Getenv("ADMIN_PASSWORD")
	if passwd == "" {
		passwd = utils.GeneratePassword()
	}

	hashedPassword := hashPasswd(passwd)

	user := models.User{
		UUID:      uuid.New().String(),
		Username:  username,
		Passwd:    hashedPassword,
		SSOID:     "",
		CreatedAt: models.FromTime(time.Now()),
		UpdatedAt: models.FromTime(time.Now()),
	}

	err = db.Create(&user).Error
	if err != nil {
		return "", "", err
	}

	return username, passwd, nil
}

func GetUserByUUID(uuid string) (user models.User, err error) {
	db := dbcore.GetDBInstance()
	err = db.Where("uuid = ?", uuid).First(&user).Error
	if err != nil {
		return models.User{}, err
	}
	return user, nil
}

// 通过 SSO 信息获取用户
func GetUserBySSO(ssoID string) (user models.User, err error) {
	db := dbcore.GetDBInstance()

	// 首先尝试查找已存在的用户
	err = db.Where("sso_id = ?", ssoID).First(&user).Error
	if err == nil {
		return user, nil
	}

	// 如果找不到用户，返回明确的错误信息
	return models.User{}, fmt.Errorf("用户不存在：%s", ssoID)
}

func BindingExternalAccount(uuid string, sso_id string) error {
	db := dbcore.GetDBInstance()
	err := db.Model(&models.User{}).Where("uuid = ?", uuid).Update("sso_id", sso_id).Error
	if err != nil {
		return err
	}
	return nil
}

func UnbindExternalAccount(uuid string) error {
	db := dbcore.GetDBInstance()
	err := db.Model(&models.User{}).Where("uuid = ?", uuid).Update("sso_id", "").Error
	if err != nil {
		return err
	}
	return nil
}

func UpdateUser(uuid string, name, password, sso_type *string) error {
	db := dbcore.GetDBInstance()
	// Check if user exists
	var existingUser models.User
	result := db.Where("uuid = ?", uuid).First(&existingUser)
	if result.Error != nil {
		return fmt.Errorf("user not found: %s", uuid)
	}
	updates := make(map[string]interface{})
	if name != nil {
		updates["username"] = *name
	}
	if password != nil {
		updates["passwd"] = hashPasswd(*password)
	}
	if sso_type != nil {
		updates["sso_type"] = *sso_type
	}
	updates["updated_at"] = time.Now()
	err := db.Model(&models.User{}).Where("uuid = ?", uuid).Updates(updates).Error
	if err != nil {
		return err
	}
	if password != nil {
		DeleteAllSessions()
	}
	return nil
}

// GetUserByCloudflareAccess 通过 Cloudflare Access email 获取用户
func GetUserByCloudflareAccess(email string) (user models.User, err error) {
	db := dbcore.GetDBInstance()
	
	// 查找 SSO 类型为 cloudflare_access 且 SSO ID 为 email 的用户
	err = db.Where("sso_type = ? AND sso_id = ?", "cloudflare_access", email).First(&user).Error
	if err != nil {
		return models.User{}, fmt.Errorf("Cloudflare Access user not found: %s", email)
	}
	
	return user, nil
}

// CreateCloudflareAccessUser 创建 Cloudflare Access 用户
func CreateCloudflareAccessUser(email, sub string) (user models.User, err error) {
	db := dbcore.GetDBInstance()
	
	// 使用 email 作为用户名，生成随机密码（不会被使用）
	hashedPassword := hashPasswd(utils.GeneratePassword())
	
	user = models.User{
		UUID:      uuid.New().String(),
		Username:  email,
		Passwd:    hashedPassword,
		SSOType:   "cloudflare_access",
		SSOID:     email,
		CreatedAt: models.FromTime(time.Now()),
		UpdatedAt: models.FromTime(time.Now()),
	}
	
	err = db.Create(&user).Error
	if err != nil {
		return models.User{}, err
	}
	
	return user, nil
}

// BindCloudflareAccess 绑定 Cloudflare Access 到现有用户
func BindCloudflareAccess(uuid, email string) error {
	db := dbcore.GetDBInstance()
	
	// 检查是否已有其他用户绑定了这个 email
	var existingUser models.User
	result := db.Where("sso_type = ? AND sso_id = ?", "cloudflare_access", email).First(&existingUser)
	if result.Error == nil && existingUser.UUID != uuid {
		return fmt.Errorf("this Cloudflare Access account is already bound to another user")
	}
	
	// 绑定到指定用户
	err := db.Model(&models.User{}).Where("uuid = ?", uuid).Updates(map[string]interface{}{
		"sso_type": "cloudflare_access",
		"sso_id":   email,
	}).Error
	
	return err
}

// UnbindCloudflareAccess 解绑 Cloudflare Access
func UnbindCloudflareAccess(uuid string) error {
	db := dbcore.GetDBInstance()
	
	err := db.Model(&models.User{}).Where("uuid = ? AND sso_type = ?", uuid, "cloudflare_access").Updates(map[string]interface{}{
		"sso_type": "",
		"sso_id":   "",
	}).Error
	
	return err
}

// GetUserSessions 获取用户的所有会话
func GetUserSessions(uuid string) ([]models.Session, error) {
	db := dbcore.GetDBInstance()
	var sessions []models.Session
	
	err := db.Where("uuid = ? AND expires > ?", uuid, time.Now()).Find(&sessions).Error
	if err != nil {
		return nil, err
	}
	
	return sessions, nil
}
