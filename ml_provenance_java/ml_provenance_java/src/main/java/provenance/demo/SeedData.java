package provenance.demo;

import provenance.ProvenanceSystem;
import java.util.*;

/**
 * SeedData — builds a realistic ML supply chain provenance graph.
 *
 * Pipeline:
 *   Public Datasets → Base Models → Fine-tuned Models → Products
 *
 * Mirrors real-world dependencies:
 *   ImageNet  → ResNet-50  → ImageClassifier → ContentModerationAPI
 *   The Pile  → GPT-2      → AcmeLLM-7B     → AcmeChatbot
 *   LAION-5B  → CLIP       → AcmeVision-7B  → VisionAnalyticsAPI
 *   CommonVoice → BERT → STT-English → TranscriptionService
 */
public class SeedData {

    public static ProvenanceSystem buildDemoSystem() {
        ProvenanceSystem ps = new ProvenanceSystem();

        // ── Datasets ──────────────────────────────────────────────────────
        ps.ingestArtifact("ds_imagenet", "dataset", map(
            "name","ImageNet-1K","version","2012","sizeGb",138,
            "samples",1281167,"source","image-net.org"
        ), "ImageNet-Team");

        ps.ingestArtifact("ds_commonvoice", "dataset", map(
            "name","Mozilla CommonVoice","version","13.0","sizeGb",80,
            "languages",108,"source","commonvoice.mozilla.org"
        ), "Mozilla");

        ps.ingestArtifact("ds_pile", "dataset", map(
            "name","The Pile","version","1.0","sizeGb",825,
            "tokensB",300,"source","EleutherAI"
        ), "EleutherAI");

        ps.ingestArtifact("ds_laion", "dataset", map(
            "name","LAION-5B","version","2.0","sizeGb",240,
            "pairs","5B image-text","source","laion.ai"
        ), "LAION");

        // ── Tools / Training Scripts ──────────────────────────────────────
        ps.ingestArtifact("tool_trainer", "tool", map(
            "name","PyTorch Trainer","version","2.1.0",
            "framework","pytorch"
        ), "Meta-AI");

        ps.ingestArtifact("tool_tokenizer", "tool", map(
            "name","HuggingFace Tokenizer","version","4.35.0","type","BPE"
        ), "HuggingFace");

        ps.ingestArtifact("tool_cliptrainer", "tool", map(
            "name","OpenCLIP Trainer","version","2.20.0"
        ), "MLFoundations");

        ps.ingestArtifact("tool_rlhf", "tool", map(
            "name","RLHF Pipeline","version","1.4.0","method","PPO"
        ), "CarperAI");

        // ── Base / Pretrained Models ──────────────────────────────────────
        ps.ingestArtifact("model_resnet50", "model", map(
            "name","ResNet-50","paramsM",25.6,"accuracyTop1",76.1,
            "architecture","CNN"
        ), "Microsoft-Research");

        ps.ingestArtifact("model_vit_base", "model", map(
            "name","ViT-Base-16","paramsM",86,"accuracyTop1",81.4,
            "architecture","Transformer","patchSize",16
        ), "Google-Brain");

        ps.ingestArtifact("model_gpt2", "model", map(
            "name","GPT-2","paramsM",117,"contextLength",1024,
            "architecture","GPT","vocabSize",50257
        ), "OpenAI");

        ps.ingestArtifact("model_bert", "model", map(
            "name","BERT-Base","paramsM",110,"layers",12,
            "hiddenSize",768,"architecture","BERT"
        ), "Google");

        ps.ingestArtifact("model_clip", "model", map(
            "name","CLIP-ViT-L-14","paramsM",307,"zeroShotAcc",75.3,
            "modalities","image+text"
        ), "OpenAI");

        // ── Fine-tuned Models ─────────────────────────────────────────────
        ps.ingestArtifact("model_classifier_v1", "model", map(
            "name","ImageClassifier-v1","paramsM",25.6,
            "task","classification","classes",1000,"accuracy",89.3
        ), "Acme-ML");

        ps.ingestArtifact("model_stt_en", "model", map(
            "name","STT-English-v2","paramsM",74,
            "task","speech-to-text","wer",4.2,"language","en"
        ), "Acme-ML");

        ps.ingestArtifact("model_llm_7b", "model", map(
            "name","AcmeLLM-7B","paramsB",7,
            "task","text-generation","contextLength",4096
        ), "Acme-ML");

        ps.ingestArtifact("model_llm_chat", "model", map(
            "name","AcmeLLM-Chat-7B","paramsB",7,
            "task","chat","rlhf",true,"safetyTrained",true
        ), "Acme-ML");

        ps.ingestArtifact("model_multimodal", "model", map(
            "name","AcmeVision-7B","paramsB",7.3,
            "task","image-text","modalities","image+text"
        ), "Acme-ML");

        // ── Products ──────────────────────────────────────────────────────
        ps.ingestArtifact("prod_content_mod", "product", map(
            "name","ContentModerationAPI","version","3.1",
            "deployment","aws-us-east-1","customers",240
        ), "Acme-Product");

        ps.ingestArtifact("prod_search", "product", map(
            "name","SemanticSearchEngine","version","2.4",
            "deployment","gcp-us-central1","queriesPerDay",5000000
        ), "Acme-Product");

        ps.ingestArtifact("prod_chatbot", "product", map(
            "name","AcmeChatbot","version","1.2",
            "deployment","azure-eastus","activeUsers",80000
        ), "Acme-Product");

        ps.ingestArtifact("prod_transcription", "product", map(
            "name","TranscriptionService","version","4.0",
            "deployment","aws-eu-west-1","minutesPerDay",200000
        ), "Acme-Product");

        ps.ingestArtifact("prod_vision_api", "product", map(
            "name","VisionAnalyticsAPI","version","1.0",
            "deployment","gcp-asia-east1","customers",55
        ), "Acme-Product");

        // ── Edges: Provenance Dependencies ───────────────────────────────
        // Datasets → Base Models
        ps.addDependency("ds_imagenet",     "model_resnet50",   0.95);
        ps.addDependency("tool_trainer",    "model_resnet50",   0.80);
        ps.addDependency("ds_imagenet",     "model_vit_base",   0.95);
        ps.addDependency("tool_trainer",    "model_vit_base",   0.80);
        ps.addDependency("ds_pile",         "model_gpt2",       0.90);
        ps.addDependency("tool_trainer",    "model_gpt2",       0.75);
        ps.addDependency("tool_tokenizer",  "model_gpt2",       0.70);
        ps.addDependency("ds_pile",         "model_bert",       0.90);
        ps.addDependency("tool_tokenizer",  "model_bert",       0.70);
        ps.addDependency("ds_imagenet",     "model_clip",       0.80);
        ps.addDependency("ds_laion",        "model_clip",       0.92);
        ps.addDependency("tool_cliptrainer","model_clip",       0.85);

        // Base Models → Fine-tuned Models
        ps.addDependency("model_resnet50",  "model_classifier_v1", 0.92);
        ps.addDependency("ds_imagenet",     "model_classifier_v1", 0.70);
        ps.addDependency("model_bert",      "model_stt_en",        0.85);
        ps.addDependency("ds_commonvoice",  "model_stt_en",        0.90);
        ps.addDependency("tool_trainer",    "model_stt_en",        0.65);
        ps.addDependency("model_gpt2",      "model_llm_7b",        0.88);
        ps.addDependency("ds_pile",         "model_llm_7b",        0.75);
        ps.addDependency("model_llm_7b",    "model_llm_chat",      0.90);
        ps.addDependency("tool_rlhf",       "model_llm_chat",      0.80);
        ps.addDependency("model_vit_base",  "model_multimodal",    0.85);
        ps.addDependency("model_llm_chat",  "model_multimodal",    0.82);
        ps.addDependency("model_clip",      "model_multimodal",    0.78);

        // Fine-tuned Models → Products
        ps.addDependency("model_classifier_v1", "prod_content_mod",   0.95);
        ps.addDependency("model_clip",           "prod_search",        0.90);
        ps.addDependency("model_multimodal",     "prod_search",        0.85);
        ps.addDependency("model_llm_chat",       "prod_chatbot",       0.95);
        ps.addDependency("model_stt_en",         "prod_transcription", 0.95);
        ps.addDependency("model_multimodal",     "prod_vision_api",    0.92);
        ps.addDependency("model_classifier_v1",  "prod_vision_api",    0.75);

        return ps;
    }

    /** Convenience helper to build a map from varargs key-value pairs. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> map(Object... kvPairs) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kvPairs.length - 1; i += 2) {
            m.put((String) kvPairs[i], kvPairs[i + 1]);
        }
        return m;
    }
}
