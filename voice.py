# Import required libraries
from resemblyzer import VoiceEncoder, preprocess_wav
from pathlib import Path
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity

def compare_voice_samples(path1, path2):
    # Load and preprocess the audio files
    # This step prepares the audio for analysis (resampling, normalization, etc.)
    wav1 = preprocess_wav(Path(path1))
    wav2 = preprocess_wav(Path(path2))

    # Initialize the voice encoder
    # This loads a pre-trained neural network to extract voice features
    encoder = VoiceEncoder()

    # Extract embeddings
    # Embeddings are numerical representations of the voice characteristics
    embed1 = encoder.embed_utterance(wav1)
    embed2 = encoder.embed_utterance(wav2)

    # Compute cosine similarity
    # This measures how similar the voice patterns are (0 = not similar, 1 = very similar)
    similarity = cosine_similarity(embed1.reshape(1, -1), embed2.reshape(1, -1))[0][0]
    return similarity

if __name__ == "__main__":
    # Replace these paths with your audio files
    # Make sure the files are in the same directory as this script, or use full paths
    audio1_path = "LJ025-0076.wav"
    audio2_path = "LJ037-0171.wav"

    # Compare the two audio samples and print the result
    similarity_score = compare_voice_samples(audio1_path, audio2_path)
    print(f"Similarity score: {similarity_score:.4f}")

    # If the score is high (close to 1), the voices are similar
    # If the score is low (close to 0), the voices are different
    if similarity_score > 0.7:
        print("The voices are very similar.")
    else:
        print("The voices are not similar.")
