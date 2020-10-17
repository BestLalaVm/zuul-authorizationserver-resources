package saas.resourceserver.responses;

public class UserResponse {
    private final String username;

    public UserResponse(String username) {
        this.username = username;
    }

    public String getUsername() {
        return username;
    }
}
