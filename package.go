// TO CHANGE: version - v1.0.2
package daytrading
import ("fmt"
"middleware/identification")

func Identification(c *gin.Context) {
	identification.IdentificationMiddleware(c)
}

func TestMain() {
	fmt.Println("TestMain")
}

func TestIdentification() {
	identification.Test()
}