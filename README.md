# Scanner de Portas TCP

Este é um simples scanner de portas TCP implementado em Python que permite verificar a disponibilidade de portas em um determinado endereço IP. O scanner oferece três modos de operação:

- **Escaneamento Sequencial:** Este modo verifica as portas em sequência, uma por vez, e exibe o estado de cada porta (aberta, fechada ou erro de conexão).

- **Escaneamento Aleatório:** Neste modo, as portas são verificadas de forma aleatória, fornecendo uma abordagem diferente para o escaneamento de portas.

- **Escaneamento Stealth:** Este modo utiliza o método stealth para verificar as portas, enviando pacotes SYN e analisando as respostas para determinar o estado das portas. Esse método pode ser mais discreto e eficiente em relação ao tráfego de rede.

## Como Usar

### Requisitos

- Python 3.x
- Pacote `scapy` (instalável via `pip install scapy`)

### Execução

Você pode executar o scanner através do terminal com o seguinte comando:

```bash
sudo python3 scanner.py <IP_ADDRESS> -p <PORTAS> -sS
```

Substitua `<IP_ADDRESS>` pelo endereço IP que deseja escanear e `<PORTAS>` pela lista de portas que deseja verificar, separadas por vírgula (ex: `80,443,8080` `200-300`). O parâmetro `-sS` indica o uso do escaneamento stealth.
Caso coloque somente o `<IP_ADDRESS>` será executado o escaneamento sequencial

### Opções Adicionais

- `-rS`: Ativa o modo de escaneamento aleatório.
- `-v`: Aumenta a verbosidade da saída. Pode ser utilizado múltiplas vezes para aumentar o nível de detalhe.
- `-sS`: Ativa o modo de escaneamento stealth
## Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues para relatar problemas ou sugestões de melhorias. Você também pode enviar pull requests para contribuir com código novo ou melhorias no código existente.
