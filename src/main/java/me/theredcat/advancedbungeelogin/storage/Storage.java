package me.theredcat.advancedbungeelogin.storage;

import java.sql.Timestamp;
import java.util.UUID;

public interface Storage {

    boolean isRegistered(UUID user);

    Timestamp lastLogin(UUID user);

    Timestamp whenRegistered(UUID user);

    Timestamp lastPasswordChange(UUID user);

    String getPasswordHashed(UUID user);

    String getPasswordSalt(UUID user);

    String getEmail(UUID user);

    void register(UUID user, Timestamp now, String hashedPassword);

    void changePassword(UUID user, String newHashed, String newSalt);

    void changeEmail(UUID user, String email);

}
