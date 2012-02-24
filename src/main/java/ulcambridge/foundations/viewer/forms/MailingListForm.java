package ulcambridge.foundations.viewer.forms;

import javax.validation.constraints.Size;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hibernate.validator.constraints.Email;
import org.hibernate.validator.constraints.NotEmpty;

public class MailingListForm {

    protected final Log logger = LogFactory.getLog(getClass());

    @NotEmpty
    @Size(max = 100)
    private String name;
    
    @NotEmpty
    @Email
    private String email;

    public void setName(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getEmail() {
        return email;
    }
       
}