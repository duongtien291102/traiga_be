package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Chicken đại diện cho 1 chiến kê đăng bán trên Chợ Gà Ba Miền lưu trong MongoDB
type Chicken struct {
	ID         primitive.ObjectID  `bson:"_id,omitempty" json:"id"`
	MS         string              `bson:"ms" json:"ms"`
	Title      string              `bson:"title" json:"title"`
	Breed      string              `bson:"breed" json:"breed"`
	BreedName  string              `bson:"breed_name" json:"breedName"`
	Chang      string              `bson:"chang" json:"chang"`
	Age        string              `bson:"age" json:"age"`
	CanVay     string              `bson:"can_vay" json:"canVay"`
	Loi        string              `bson:"loi" json:"loi"`
	DatNuoc    string              `bson:"dat_nuoc" json:"datNuoc"`
	Price      int64               `bson:"price" json:"price"`
	PriceText  string              `bson:"price_text" json:"priceText"`
	Farm       string              `bson:"farm" json:"farm"`
	SellerName string              `bson:"seller_name" json:"sellerName"`
	Phone      string              `bson:"phone" json:"phone"`
	Zalo       string              `bson:"zalo" json:"zalo"`
	Location   string              `bson:"location" json:"location"`
	Image      string              `bson:"image" json:"image"`
	VideoURL   string              `bson:"video_url,omitempty" json:"videoUrl,omitempty"`
	Note       string              `bson:"note,omitempty" json:"note,omitempty"`
	Status     string              `bson:"status" json:"status"` // "available", "sold"
	UserID     *primitive.ObjectID `bson:"user_id,omitempty" json:"userId,omitempty"`
	CreatedBy  string              `bson:"created_by,omitempty" json:"createdBy,omitempty"`
	CreatedAt  time.Time           `bson:"created_at" json:"createdAt"`
	UpdatedAt  time.Time           `bson:"updated_at" json:"updatedAt"`
}
