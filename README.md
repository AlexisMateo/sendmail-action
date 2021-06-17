# Send Email Action

An Action that sends an email.

## Usage

Make sure to set the secret crendetials in the _Secrets_ section of your repo's Settings.

```yml
- name: Send email
  uses: AlexisMateo/sendmail-action@5
  with:
    smtp-server: ${{ secrets.SMTP_SERVER }}
    smtp-server-port: ${{ secrets.SMTP_SERVER_PORT }}
    auth-user: ${{ secrets.AUTH_USER }}
    auth-password: ${{secrets.EMAIL_PASSWORD }}

    from: ${{ secrets.EMAIL_FROM }}
    to: ${{ secrets.EMAIL_RECEIVER }}

    subject: correciones a ${{ github.repository }}
    body: ${{ github.context.payload }}

    is-tls: false
    commit-message: true
```
