#ifndef TC_MODEL_H
#define TC_MODEL_H

/*
 * ML model interface for the traffic classifier.
 *
 * When a treelite-compiled XGBoost model is available, the generated C code
 * implements tc_model_predict() directly. When no model is compiled in,
 * the stub version (tc_model_stub.c) returns tc_model_available() == 0
 * and the classifier falls back to heuristics.
 */

#define TC_MODEL_N_FEATURES 20
#define TC_MODEL_N_CLASSES  8

/*
 * Run inference on a single feature vector.
 * features: float array of length TC_MODEL_N_FEATURES
 * output:   float array of length TC_MODEL_N_CLASSES (class probabilities)
 * Returns the predicted class index (argmax of output).
 */
int tc_model_predict(const float *features, float *output);

/*
 * Returns 1 if a compiled ML model is linked in, 0 if using stub.
 */
int tc_model_available(void);

#endif
