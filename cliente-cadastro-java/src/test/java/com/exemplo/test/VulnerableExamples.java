package test;

import java.io.FileReader;               // SRV-040 (FileReader()
import java.io.BufferedReader;
import java.io.IOException;

public class VulnerableExamples {

    // =========================
    // SEGREDOS / CREDENCIAIS
    // =========================

    // SRV-001: hardcoded api key  (regex: (api[_-]?key|access[_-]?token|authorization)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["'])
    static final String API_KEY = "AKIAIOSFODNN7EXAMPLE";   // >=16 chars

    // SRV-003: atribuição de segredo
    static final String SECRET_KEY = "superSecreta123";     // matches \b(SECRET_KEY|API_KEY|TOKEN|PASSWORD|DB_PASS|ACCESS_KEY)\b\s*=\s*["']...

    // SRV-004: segredo vazio/nulo
    static final String PASSWORD = "";                      // ... = ""  (vazio)

    // =========================
    // INJEÇÕES / EXECUÇÃO
    // =========================

    public String sqlByConcat(String userId) {
        // SRV-030: SQL injection (regex procura "SELECT * FROM" etc.)
        String q = "SELECT * FROM users WHERE id='" + userId + "'"; // concatenação
        return q;
    }

    public void commandExec(String userArg) throws Exception {
        // SRV-032: execução de comando do SO (Runtime.getRuntime().exec)
        Runtime.getRuntime().exec("sh -c id"); // caso simples

        // SRV-033: comando concatenado  (regex: exec\(".*"\s*\+\s*\w+)
        Runtime.getRuntime().exec("cat /etc/passwd | grep " + userArg);
    }

    // =========================
    // ENTRADA / ARQUIVOS
    // =========================

    public void readFileUnvalidated(String path) throws Exception {
        // SRV-040: leitura de arquivo sem validação (regex: FileReader\()
        try (FileReader fr = new FileReader(path);
             BufferedReader br = new BufferedReader(fr)) {
            String line = br.readLine();
        }
    }

    // =========================
    // XSS / HTML (sinks)
    // =========================

    public String renderHtml(String userInput) {
        // SRV-060: XSS sink (regex inclui "<script>")
        // Basta conter "<script>" para disparar; aqui simulamos renderização insegura:
        return "<html><body>" + userInput + "<script>alert('xss');</script></body></html>";
    }

    // =========================
    // PRÁTICAS / ERROS
    // =========================

    public void genericCatch() {
        try {
            throw new IOException("boom");
        } catch (Exception e) {            // SRV-070: exceção genérica (regex: catch\s*\(Exception)
            System.out.print(e.getMessage()); // SRV-071: debug/log/print (regex: print\()
        }
    }

    // =========================
    // “MENÇÃO” DE PATHS SENSÍVEIS
    // =========================

    // SRV-080: paths sensíveis expostos (menção)
    // Sua regex pega várias palavras/rotas. Estes dois exemplos disparam:
    @RequestMapping("/clientes")
    public String clientes() { return "ok"; }

    // mesmo sem Spring, a menção simples num comentário ou string também aciona:
    String caminhoSensivel = "/admin/painel"; // "/admin" está na regex de menção
}
